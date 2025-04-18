-- server.lua: Pure Lua HTTP server for secure login/register
-- No frameworks, only LuaSocket and basic file I/O
local socket = require('socket')
local json = require('dkjson') -- You may need to provide this or use a simple JSON module
-- local crypto = require('crypto') -- You may need to provide a Lua crypto module for hashing
-- local lfs = require('lfs') -- Removed: not used in this file
local http = require('socket.http')
local ltn12 = require('ltn12')
local utils = require('lua_server.utils')
local session = require('lua_server.session')
local userdb = require('lua_server.user')
local captcha = require('lua_server.captcha')
local routes = require('lua_server.routes')

local features = {}
features.email = require('lua_features.email')
features.session = require('lua_features.session')
features.email_verification = require('lua_features.email_verification')
features.mfa = require('lua_features.mfa')
-- Add more as you modularize (e.g., features.captcha = require('lua_features.captcha'))

-- Config
local PORT = 8080
local USER_DB = 'users.db'
local SESSION_DB = 'sessions.db'
local RATE_LIMIT_DB = 'ratelimit.db'

-- Helper: Password hashing (Argon2id/PBKDF2 preferred, fallback to salted SHA-256)
local function hash_password(password, salt)
  -- Replace with Argon2id/PBKDF2 if available
  return crypto.digest('sha256', salt .. password)
end

-- Helper: Argon2id password hashing via Go helper
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

-- Helper: Google reCAPTCHA verification via Go helper
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

-- Helper: Serve static files
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
    client:send('HTTP/1.1 200 OK\r\nContent-Type: '..(mime[ext] or 'application/octet-stream')..'\r\n\r\n')
    client:send(data)
  else
    client:send('HTTP/1.1 404 Not Found\r\n\r\n')
  end
end

-- Helper: Send JSON response
local function send_json(client, tbl)
  local body = json.encode(tbl)
  client:send('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n')
  client:send(body)
end

-- Helper: Parse POST body
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

-- HTTP server
local server = assert(socket.bind('*', PORT))
print('Server running on port '..PORT)

while true do
  local client = server:accept()
  client:settimeout(1)
  local req = client:receive('*l')
  if req then
    -- Simple HTTPS redirect logic (best effort, for direct server use)
    local headers = {}
    local line = req
    repeat
      line = client:receive('*l')
      if line and line ~= '' then
        local k, v = line:match('^(.-):%s*(.*)')
        if k and v then headers[k:lower()] = v end
      end
    until not line or line == ''
    local host = headers['host'] or ''
    local x_forwarded_proto = headers['x-forwarded-proto']
    if x_forwarded_proto == 'http' or (host:find(':8080') and not x_forwarded_proto) then
      local redirect_url = 'https://'..host:gsub(':8080', '')..'/'
      client:send('HTTP/1.1 301 Moved Permanently\r\nLocation: '..redirect_url..'\r\nContent-Type: text/html\r\n\r\n')
      client:send('<h2>Redirecting to secure site...</h2>')
      client:close()
      goto continue
    end

    local method, path = req:match('^(%w+)%s+([^%s]+)')
    if path:find('^/static/') then
      routes.handle_static(client, path)
    elseif path == '/' then
      routes.handle_root(client)
    elseif path == '/captcha' then
      routes.handle_captcha(client)
    elseif path == '/register' and method == 'POST' then
      routes.handle_register(client, req)
    elseif path == '/mfa_setup_info' then
      routes.handle_mfa_setup_info(client)
    elseif path == '/mfa_setup_verify' and method == 'POST' then
      routes.handle_mfa_setup_verify(client, req)
    elseif path:find('^/verify') then
      routes.handle_verify(client, path)
    elseif path == '/login' and method == 'POST' then
      routes.handle_login(client, req)
    elseif path == '/me' then
      routes.handle_me(client, req)
    elseif path == '/logout' then
      routes.handle_logout(client, req)
    elseif path == '/delete_account' and method == 'POST' then
      routes.handle_delete_account(client, req)
    else
      routes.handle_404(client)
    end
  end
  ::continue::
  client:close()
end