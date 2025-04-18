local json = require('dkjson')

local M = {}
local USER_DB = 'users.db'

function M.generate_token(len)
  local t = {}
  for i = 1, len do t[i] = string.char(math.random(33, 126)) end
  return table.concat(t)
end

function M.set_verification_token(email)
  local users = {}
  local f = io.open(USER_DB, 'r')
  if f then users = json.decode(f:read('*a')) or {} f:close() end
  local token = M.generate_token(32)
  local expiry = os.time() + 3600 -- 1 hour expiry
  if users[email] then
    users[email].verify_token = token
    users[email].verify_expiry = expiry
    local f2 = io.open(USER_DB, 'w')
    f2:write(json.encode(users))
    f2:close()
    return token
  end
  return nil
end

function M.verify_token(token)
  local f = io.open(USER_DB, 'r')
  if not f then return false end
  local users = json.decode(f:read('*a')) or {}
  f:close()
  for email, user in pairs(users) do
    if user.verify_token == token and user.verify_expiry and os.time() < user.verify_expiry then
      user.verified = true
      user.verify_token = nil
      user.verify_expiry = nil
      local f2 = io.open(USER_DB, 'w')
      f2:write(json.encode(users))
      f2:close()
      return true, email
    end
  end
  return false
end

return M
