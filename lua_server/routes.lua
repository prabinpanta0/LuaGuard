local utils = require('lua_server.utils')
local session = require('lua_server.session')
local userdb = require('lua_server.user')
local captcha = require('lua_server.captcha')
local features = {}
features.email = require('lua_features.email')
features.email_verification = require('lua_features.email_verification')
features.mfa = require('lua_features.mfa')
local json = require('dkjson')
local http = require('socket.http')
local ltn12 = require('ltn12')

local USER_DB = 'users.db'
local SESSION_DB = 'sessions.db'
local RATE_LIMIT_DB = 'ratelimit.db'
local PORT = 8080

local MFA_KEY = os.getenv('MFA_SECRET_KEY') or 'default_xor_key_2025' -- Set a strong key in production!

local function xor_encrypt_decrypt(str, key)
  local out = {}
  for i = 1, #str do
    local k = key:byte(((i - 1) % #key) + 1)
    out[i] = string.char(bit32.bxor(str:byte(i), k))
  end
  return table.concat(out)
end

local function hash_password_argon2id(password, salt)
  local req_body = json.encode({password = password, salt = salt})
  local resp_body = {}
  http.request{
    url = 'http://127.0.0.1:8081/hash',
    method = 'POST',
    headers = {
      ['Content-Type'] = 'application/json',
      ['Content-Length'] = tostring(#req_body)
    },
    source = ltn12.source.string(req_body),
    sink = ltn12.sink.table(resp_body)
  }
  local resp = table.concat(resp_body)
  local data = json.decode(resp)
  return data.hash, data.salt
end

local function verify_recaptcha(token)
  local recaptcha_secret = os.getenv('RECAPTCHA_SECRET')
  if not recaptcha_secret then
    return false -- Fail securely if secret is missing
  end
  local req_body = json.encode({token = token, secret = recaptcha_secret})
  local resp_body = {}
  http.request{
    url = 'http://127.0.0.1:8081/recaptcha',
    method = 'POST',
    headers = {
      ['Content-Type'] = 'application/json',
      ['Content-Length'] = tostring(#req_body)
    },
    source = ltn12.source.string(req_body),
    sink = ltn12.sink.table(resp_body)
  }
  local resp = table.concat(resp_body)
  local data = json.decode(resp)
  return data.success == true
end

local function send_security_headers(client)
  client:send('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n')
  client:send('Content-Security-Policy: default-src \'self\'\r\n')
  client:send('X-Frame-Options: DENY\r\n')
  client:send('X-Content-Type-Options: nosniff\r\n')
  client:send('Referrer-Policy: no-referrer\r\n')
  client:send('Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n')
end

local function serve_static(client, path)
  local static_path = 'static' .. path:gsub('^/static', '')
  local ext = static_path:match('%.([a-zA-Z0-9]+)$') or ''
  local mime = {
    html = 'text/html', css = 'text/css', js = 'application/javascript',
    png = 'image/png', jpg = 'image/jpeg', jpeg = 'image/jpeg',
  }
  local f = io.open(static_path, 'rb')
  if f then
    local data = f:read('*a')
    f:close()
    client:send('HTTP/1.1 200 OK\r\nContent-Type: '..(mime[ext] or 'application/octet-stream')..'\r\n')
    send_security_headers(client)
    client:send('\r\n')
    client:send(data)
  else
    client:send('HTTP/1.1 404 Not Found\r\n')
    send_security_headers(client)
    client:send('\r\n')
  end
end

local function send_json(client, tbl)
  local body = json.encode(tbl)
  client:send('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n')
  send_security_headers(client)
  client:send('\r\n')
  client:send(body)
end

local function parse_post(client, req)
  local headers = {}
  local line
  repeat
    line = client:receive('*l')
    if line and line ~= '' then
      local k, v = line:match('^(.-):%s*(.*)')
      if k and v then headers[k:lower()] = v end
    end
  until not line or line == ''
  local len = tonumber(headers['content-length'] or '0')
  local body = ''
  if len > 0 then body = client:receive(len) end
  return body, headers
end

local function get_qr_code_data_url(url)
  local req_body = json.encode({url = url})
  local resp_body = {}
  local ok, code, headers, status = http.request{
    url = 'http://127.0.0.1:8081/qrcode',
    method = 'POST',
    headers = {
      ['Content-Type'] = 'application/json',
      ['Content-Length'] = tostring(#req_body)
    },
    source = ltn12.source.string(req_body),
    sink = ltn12.sink.table(resp_body)
  }
  if ok and code == 200 then
    local resp = table.concat(resp_body)
    local data = json.decode(resp)
    return data.data_url, data.error
  else
    print('Error calling QR code helper:', code, status)
    return nil, 'Failed to generate QR code'
  end
end

local routes = {}
local captcha_answers = {}
local csrf_tokens = {}

local function set_csrf_token(client)
  local token = utils.random_string(32)
  csrf_tokens[token] = os.time()
  client:send('Set-Cookie: csrf_token='..token..'; SameSite=Strict; Path=/; Secure\r\n')
  return token
end

local function get_csrf_token_from_cookie(headers)
  local cookie = headers['cookie'] or ''
  return cookie:match('csrf_token=([%w%p]+)')
end

local function validate_csrf(headers, data)
  local cookie_token = get_csrf_token_from_cookie(headers)
  local req_token = (data and data.csrf_token) or headers['x-csrf-token']
  if not cookie_token or not req_token or cookie_token ~= req_token then
    return false
  end
  if not csrf_tokens[cookie_token] then return false end
  csrf_tokens[cookie_token] = nil -- Invalidate after use
  return true
end

function routes.handle_captcha(client)
  local q, a = captcha.generate_captcha()
  local token = utils.random_string(16)
  captcha_answers[token] = {answer=a, ts=os.time()}
  send_json(client, {q=q, token=token})
end

local function is_valid_email(email)
  -- Simple RFC 5322-compliant pattern (not perfect, but good for most cases)
  return type(email) == 'string' and email:match('^[A-Za-z0-9._%%+-]+@[A-Za-z0-9.-]+%.[A-Za-z]{2,}$') ~= nil
end

local function sanitize(str)
  if type(str) ~= 'string' then return '' end
  -- Remove control chars, trim, and collapse whitespace
  str = str:gsub('[%z\1-\31]', '')
  str = str:gsub('^%s+', ''):gsub('%s+$', '')
  str = str:gsub('%s+', ' ')
  return str
end

-- Per-user rate limiting (in addition to per-IP)
local function check_user_rate_limit(email, db_path)
  local rl = utils.read_db(db_path)
  local now = os.time()
  rl[email] = rl[email] or {count=0, last=now}
  if now - rl[email].last > 3600 then rl[email] = {count=0, last=now} end
  rl[email].count = rl[email].count + 1
  rl[email].last = now
  utils.write_db(db_path, rl)
  return rl[email].count <= 5
end

local function is_pwned_password(password)
  local sha1 = require('lua_features.sha1')
  local http = require('socket.http')
  local hash = sha1.sum(password):upper()
  local prefix = hash:sub(1,5)
  local suffix = hash:sub(6)
  local url = 'https://api.pwnedpasswords.com/range/'..prefix
  local body = {}
  local _, code = http.request{
    url = url,
    sink = ltn12.sink.table(body),
    method = 'GET',
    headers = {['User-Agent']='LuaPwnedCheck'}
  }
  if code ~= 200 then return false end -- Fail open if API unavailable
  local resp = table.concat(body)
  for line in resp:gmatch('[^\r\n]+') do
    local found_suffix = line:match('^([A-F0-9]+):')
    if found_suffix and found_suffix == suffix then
      return true
    end
  end
  return false
end

local function hash_recovery_code(code)
  local sha1 = require('lua_features.sha1')
  return sha1.sum(code)
end

local function generate_recovery_codes(n)
  local codes = {}
  for i=1,n do
    local code = utils.random_string(10)
    table.insert(codes, code)
  end
  return codes
end

function routes.handle_register(client, req)
  local body, headers = parse_post(client, req)
  local data = json.decode(body)
  if not validate_csrf(headers, data) then
    send_json(client, {ok=false, msg='CSRF validation failed'})
    return
  end
  if not data or not data.email or not data.password or not data.captcha or not data.captcha_token or not data.recaptcha_token then
    send_json(client, {ok=false, msg='Missing fields'})
    return
  end
  data.email = sanitize(data.email)
  if not is_valid_email(data.email) then
    send_json(client, {ok=false, msg='Invalid email format'})
    return
  end
  if is_pwned_password(data.password) then
    send_json(client, {ok=false, msg='This password has been found in a data breach. Please choose a different password.'})
    return
  end
  if not verify_recaptcha(data.recaptcha_token) then
    send_json(client, {ok=false, msg='reCAPTCHA failed'})
  elseif not captcha_answers[data.captcha_token] or captcha_answers[data.captcha_token].answer ~= data.captcha then
    send_json(client, {ok=false, msg='Invalid CAPTCHA'})
  elseif #data.password < 8 then
    send_json(client, {ok=false, msg='Password too short'})
  else
    captcha_answers[data.captcha_token] = nil -- Remove used token
    local ip = 'unknown' -- For demo, real IP parsing needed
    if not utils.check_rate_limit(ip, RATE_LIMIT_DB) or not check_user_rate_limit(data.email, RATE_LIMIT_DB) then
      send_json(client, {ok=false, msg='Too many attempts'})
    else
      local users = utils.read_db(USER_DB)
      if users[data.email] then
        send_json(client, {ok=false, msg='User already exists'})
      else
        local salt = nil
        local hash, salt = hash_password_argon2id(data.password, salt)
        local mfa_secret = features.mfa.random_secret(16)
        local enc_mfa_secret = xor_encrypt_decrypt(mfa_secret, MFA_KEY)
        local recovery_codes = generate_recovery_codes(5)
        local hashed_codes = {}
        for _, code in ipairs(recovery_codes) do table.insert(hashed_codes, hash_recovery_code(code)) end
        users[data.email] = {hash=hash, salt=salt, verified=false, mfa_secret=enc_mfa_secret, recovery_codes=hashed_codes}
        utils.write_db(USER_DB, users)
        local token = features.email_verification.set_verification_token(data.email)
        local verify_link = 'http://localhost:'..PORT..'/verify?token='..token
        features.email.send_verification_email(data.email, 'Verify your account', 'Click to verify: '..verify_link..'\nMFA Secret: '..mfa_secret)
        send_json(client, {ok=true, mfa_setup=true, recovery_codes=recovery_codes})
      end
    end
  end
end

function routes.handle_mfa_setup_info(client)
  local users = utils.read_db(USER_DB)
  local last_email, last_user
  for email, user in pairs(users) do last_email, last_user = email, user end -- Demo: Get last user
  if last_user and last_user.mfa_secret then
    local mfa_secret = xor_encrypt_decrypt(last_user.mfa_secret, MFA_KEY)
    local otpauth_url = string.format("otpauth://totp/SecureApp:%s?secret=%s&issuer=SecureApp",
                                    utils.url_encode(last_email), mfa_secret)
    local qr_data_url, qr_error = get_qr_code_data_url(otpauth_url)
    if qr_data_url then
      local recovery_codes = last_user.recovery_codes or {}
      send_json(client, {ok=true, secret=mfa_secret, email=last_email, qr_code_data_url=qr_data_url, recovery_codes=recovery_codes})
    else
      send_json(client, {ok=false, msg=qr_error or 'Failed to generate QR code'})
    end
  else
    send_json(client, {ok=false, msg='No user or MFA secret found'})
  end
end

function routes.handle_mfa_setup_verify(client, req)
  local body = parse_post(client, req)
  local data = json.decode(body)
  if not data or not data.code then
    send_json(client, {ok=false, msg='Missing code'})
    return
  end
  local users = utils.read_db(USER_DB)
  local last_email, last_user
  for email, user in pairs(users) do last_email, last_user = email, user end
  if not last_user then
    send_json(client, {ok=false, msg='No user'})
    return
  end
  -- Account lockout logic
  local now = os.time()
  last_user.mfa_fail_count = last_user.mfa_fail_count or 0
  last_user.mfa_lock_until = last_user.mfa_lock_until or 0
  if last_user.mfa_lock_until > now then
    send_json(client, {ok=false, locked=true, msg='Account locked due to too many failed MFA attempts. Try again later.'})
    return
  end
  if features.mfa.verify_totp(xor_encrypt_decrypt(last_user.mfa_secret, MFA_KEY), data.code) then
    last_user.mfa_fail_count = 0
    last_user.mfa_lock_until = 0
    users[last_email] = last_user
    utils.write_db(USER_DB, users)
    send_json(client, {ok=true})
  else
    last_user.mfa_fail_count = last_user.mfa_fail_count + 1
    last_user.last_mfa_fail = now
    if last_user.mfa_fail_count >= 5 then
      last_user.mfa_lock_until = now + 3600 -- 1 hour lock
      last_user.mfa_fail_count = 0
    end
    users[last_email] = last_user
    utils.write_db(USER_DB, users)
    if last_user.mfa_lock_until > now then
      send_json(client, {ok=false, locked=true, msg='Account locked due to too many failed MFA attempts. Try again later.'})
    else
      send_json(client, {ok=false, msg='Invalid code'})
    end
  end
end

function routes.handle_mfa_verify(client, req)
  local body = parse_post(client, req)
  local data = json.decode(body)
  if not data or not data.email or not data.code then
    send_json(client, {ok=false, msg='Missing fields'})
    return
  end
  local users = utils.read_db(USER_DB)
  local user = users[data.email]
  if not user then
    send_json(client, {ok=false, msg='User not found'})
    return
  end
  local now = os.time()
  user.mfa_fail_count = user.mfa_fail_count or 0
  user.mfa_lock_until = user.mfa_lock_until or 0
  if user.mfa_lock_until > now then
    send_json(client, {ok=false, locked=true, msg='Account locked due to too many failed MFA attempts. Try again later.'})
    return
  end
  local valid = features.mfa.verify_totp(xor_encrypt_decrypt(user.mfa_secret, MFA_KEY), data.code)
  if not valid and user.recovery_codes then
    local code_hash = hash_recovery_code(data.code)
    for i, h in ipairs(user.recovery_codes) do
      if h == code_hash then
        valid = true
        table.remove(user.recovery_codes, i)
        break
      end
    end
  end
  if valid then
    user.mfa_fail_count = 0
    user.mfa_lock_until = 0
    users[data.email] = user
    utils.write_db(USER_DB, users)
    send_json(client, {ok=true})
  else
    user.mfa_fail_count = user.mfa_fail_count + 1
    user.last_mfa_fail = now
    if user.mfa_fail_count >= 5 then
      user.mfa_lock_until = now + 3600
      user.mfa_fail_count = 0
    end
    users[data.email] = user
    utils.write_db(USER_DB, users)
    if user.mfa_lock_until > now then
      send_json(client, {ok=false, locked=true, msg='Account locked due to too many failed MFA attempts. Try again later.'})
    else
      send_json(client, {ok=false, msg='Invalid code'})
    end
  end
end

function routes.handle_verify(client, path)
  local token = path:match('token=([%w%p]+)')
  if not token then
    client:send('HTTP/1.1 400 Bad Request\r\n\r\n')
  else
    local ok, email = features.email_verification.verify_token(token)
    if ok then
      client:send('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n')
      send_security_headers(client)
      client:send('\r\n')
      client:send('<h2>Email verified!</h2><p>You may now log in.</p>')
    else
      client:send('HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n')
      send_security_headers(client)
      client:send('\r\n')
      client:send('<h2>Invalid or expired token.</h2>')
    end
  end
end

function routes.handle_login(client, req)
  local body, headers = parse_post(client, req)
  local data = json.decode(body)
  if not validate_csrf(headers, data) then
    send_json(client, {ok=false, msg='CSRF validation failed'})
    return
  end
  if not data or not data.email or not data.password or not data.captcha or not data.captcha_token or not data.recaptcha_token then
    send_json(client, {ok=false, msg='Missing fields'})
    return
  end
  data.email = sanitize(data.email)
  if not is_valid_email(data.email) then
    send_json(client, {ok=false, msg='Invalid email format'})
    return
  end
  -- Behavioral biometrics risk scoring
  local risk = 0
  if data.biometrics then
    local kt = data.biometrics.keyTimings or {}
    local mm = data.biometrics.mouseMoves or {}
    -- Simple risk: if all key timings are identical or zero, or too few events, flag as risky (likely bot)
    if #kt < 3 or (#kt > 0 and (#table.concat(kt, ','):gsub('[^,]', '') == string.rep(',', #kt-1))) then
      risk = risk + 1
    end
    if #mm < 5 then risk = risk + 1 end
    -- If mouse movement is only in a straight line, flag as risky
    if #mm > 2 then
      local dx = math.abs(mm[#mm].x - mm[1].x)
      local dy = math.abs(mm[#mm].y - mm[1].y)
      if dx == 0 or dy == 0 then risk = risk + 1 end
    end
  else
    risk = risk + 1 -- No biometrics provided
  end
  -- If risk is high, always require MFA
  if risk >= 2 then
    send_json(client, {ok=true, mfa_required=true, msg='Unusual login behavior detected. MFA required.'})
    return
  end
  if not verify_recaptcha(data.recaptcha_token) then
    send_json(client, {ok=false, msg='reCAPTCHA failed'})
  elseif not captcha_answers[data.captcha_token] or captcha_answers[data.captcha_token].answer ~= data.captcha then
    send_json(client, {ok=false, msg='Invalid CAPTCHA'})
  else
    captcha_answers[data.captcha_token] = nil -- Remove used token
    local ip = 'unknown' -- For demo, real IP parsing needed
    if not utils.check_rate_limit(ip, RATE_LIMIT_DB) or not check_user_rate_limit(data.email, RATE_LIMIT_DB) then
      send_json(client, {ok=false, msg='Too many attempts'})
    else
      local users = utils.read_db(USER_DB)
      local user = users[data.email]
      if not user then
        send_json(client, {ok=false, msg='User not found'})
      elseif user.hash ~= (function()
        local hash, _ = hash_password_argon2id(data.password, user.salt)
        return hash
      end)() then
        send_json(client, {ok=false, msg='Incorrect password'})
      elseif not user.verified then
        send_json(client, {ok=false, msg='Email not verified'})
      elseif user.mfa_secret and user.mfa_secret ~= '' then
        send_json(client, {ok=true, mfa_required=true})
      else
        local sessions = utils.read_db(SESSION_DB)
        local token = utils.random_string(32)
        sessions[token] = {email=data.email, ts=os.time()}
        utils.write_db(SESSION_DB, sessions)
        client:send('HTTP/1.1 200 OK\r\nSet-Cookie: session='..token..'; HttpOnly; SameSite=Strict; Secure\r\nContent-Type: application/json\r\n')
        send_security_headers(client)
        client:send('\r\n')
        client:send(json.encode({ok=true, msg='Login successful'}))
      end
    end
  end
end

function routes.handle_me(client, req)
  local headers = {}
  local line
  repeat
    line = client:receive('*l')
    if line and line ~= '' then
      local k, v = line:match('^(.-):%s*(.*)')
      if k and v then headers[k:lower()] = v end
    end
  until not line or line == ''
  local cookie = headers['cookie'] or ''
  local session_token = cookie:match('session=([%w%p]+)')
  if not session_token then
    send_json(client, {ok=false, msg='No session'})
  else
    local sessions = utils.read_db(SESSION_DB)
    local session = sessions[session_token]
    if not session then
      send_json(client, {ok=false, msg='Invalid session'})
    else
      local users = utils.read_db(USER_DB)
      local user = users[session.email]
      if not user then
        send_json(client, {ok=false, msg='User not found'})
      else
        send_json(client, {ok=true, email=session.email, verified=user.verified, log_history=user.log_history or {}})
      end
    end
  end
end

function routes.handle_logout(client, req)
  local headers = {}
  local line
  repeat
    line = client:receive('*l')
    if line and line ~= '' then
      local k, v = line:match('^(.-):%s*(.*)')
      if k and v then headers[k:lower()] = v end
    end
  until not line or line == ''
  local cookie = headers['cookie'] or ''
  local session_token = cookie:match('session=([%w%p]+)')
  if session_token then
    local sessions = utils.read_db(SESSION_DB)
    sessions[session_token] = nil
    utils.write_db(SESSION_DB, sessions)
  end
  client:send('HTTP/1.1 200 OK\r\nSet-Cookie: session=deleted; Max-Age=0; Path=/; HttpOnly; SameSite=Strict; Secure\r\nContent-Type: application/json\r\n')
  send_security_headers(client)
  client:send('\r\n')
  client:send(json.encode({ok=true}))
end

function routes.handle_delete_account(client, req)
  local headers = {}
  local line
  repeat
    line = client:receive('*l')
    if line and line ~= '' then
      local k, v = line:match('^(.-):%s*(.*)')
      if k and v then headers[k:lower()] = v end
    end
  until not line or line == ''
  local cookie = headers['cookie'] or ''
  local session_token = cookie:match('session=([%w%p]+)')
  local len = tonumber(headers['content-length'] or '0')
  local body = ''
  if len > 0 then body = client:receive(len) end
  local data = json.decode(body)
  if not session_token then
    send_json(client, {ok=false, msg='Not logged in'})
  elseif not data or not data.password then
    send_json(client, {ok=false, msg='Password required'})
  else
    local sessions = utils.read_db(SESSION_DB)
    local session = sessions[session_token]
    if not session then
      send_json(client, {ok=false, msg='Invalid session'})
    else
      local users = utils.read_db(USER_DB)
      local user = users[session.email]
      if not user then
        send_json(client, {ok=false, msg='User not found'})
      else
        local hash, _ = hash_password_argon2id(data.password, user.salt)
        if user.hash ~= hash then
          send_json(client, {ok=false, msg='Incorrect password'})
        else
          users[session.email] = nil
          utils.write_db(USER_DB, users)
          for k, v in pairs(sessions) do
            if v.email == session.email then sessions[k] = nil end
          end
          utils.write_db(SESSION_DB, sessions)
          client:send('HTTP/1.1 200 OK\r\nSet-Cookie: session=deleted; Max-Age=0; Path=/; HttpOnly; SameSite=Strict; Secure\r\nContent-Type: application/json\r\n')
          send_security_headers(client)
          client:send('\r\n')
          client:send(json.encode({ok=true}))
        end
      end
    end
  end
end

function routes.handle_static(client, path)
  serve_static(client, path)
  if path:find('login') or path:find('register') or path:find('reset') then
    set_csrf_token(client)
  end
end

function routes.handle_root(client)
  serve_static(client, '/static/index.html')
end

function routes.handle_404(client)
  client:send('HTTP/1.1 404 Not Found\r\n')
  send_security_headers(client)
  client:send('\r\n')
end

return routes