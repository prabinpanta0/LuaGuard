-- Pure Lua TOTP (RFC 6238) implementation for MFA
local M = {}
local base32 = require('lua_features.base32')
local hmac = require('lua_features.hmac_sha1')

function M.random_secret(len)
  local t = {}
  for i = 1, len do t[i] = string.char(math.random(65, 90)) end -- A-Z
  return table.concat(t)
end

function M.totp(secret, time_step)
  time_step = time_step or 30
  local key = base32.decode(secret)
  local t = math.floor(os.time() / time_step)
  local msg = string.char(
    bit32.rshift(t, 24) % 256,
    bit32.rshift(t, 16) % 256,
    bit32.rshift(t, 8) % 256,
    t % 256
  )
  local hash = hmac.sha1(key, msg)
  local offset = string.byte(hash, 20) % 16
  local code = 0
  for i = 1, 4 do
    code = bit32.lshift(code, 8) + string.byte(hash, offset + i)
  end
  code = code % 1000000
  return string.format('%06d', code)
end

function M.verify_totp(secret, code)
  return M.totp(secret) == code
end

return M
