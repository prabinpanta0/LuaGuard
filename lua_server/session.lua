local utils = require('lua_server.utils')

local M = {}

local SESSION_DB = 'sessions.db'

function M.create_session(email)
  local sessions = utils.read_db(SESSION_DB)
  local token = utils.random_string(32)
  sessions[token] = {email=email, ts=os.time()}
  utils.write_db(SESSION_DB, sessions)
  return token
end

function M.get_session(token)
  local sessions = utils.read_db(SESSION_DB)
  return sessions[token]
end

function M.delete_session(token)
  local sessions = utils.read_db(SESSION_DB)
  sessions[token] = nil
  utils.write_db(SESSION_DB, sessions)
end

function M.delete_all_sessions_for_email(email)
  local sessions = utils.read_db(SESSION_DB)
  for k, v in pairs(sessions) do
    if v.email == email then sessions[k] = nil end
  end
  utils.write_db(SESSION_DB, sessions)
end

return M
