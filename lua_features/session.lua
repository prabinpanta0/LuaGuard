local json = require('dkjson')

local M = {}

local SESSION_DB = 'sessions.db'

function M.create_session(email)
  local function random_string(len)
    local t = {}
    for i = 1, len do t[i] = string.char(math.random(33, 126)) end
    return table.concat(t)
  end
  local sessions = {}
  local f = io.open(SESSION_DB, 'r')
  if f then sessions = json.decode(f:read('*a')) or {} f:close() end
  local token = random_string(32)
  sessions[token] = {email=email, ts=os.time()}
  local f2 = io.open(SESSION_DB, 'w')
  f2:write(json.encode(sessions))
  f2:close()
  return token
end

function M.get_session(token)
  local f = io.open(SESSION_DB, 'r')
  if not f then return nil end
  local sessions = json.decode(f:read('*a')) or {}
  f:close()
  return sessions[token]
end

return M
