local utils = require('lua_server.utils')
local session = require('lua_server.session')

local M = {}

local USER_DB = 'users.db'

function M.get_user(email)
  local users = utils.read_db(USER_DB)
  return users[email]
end

function M.set_user(email, user)
  local users = utils.read_db(USER_DB)
  users[email] = user
  utils.write_db(USER_DB, users)
end

function M.delete_user(email)
  local users = utils.read_db(USER_DB)
  users[email] = nil
  utils.write_db(USER_DB, users)
end

return M
