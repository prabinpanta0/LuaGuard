local utils = require('lua_server.utils')

local M = {}

function M.generate_captcha()
  local a, b = math.random(1,9), math.random(1,9)
  return tostring(a)..'+'..tostring(b), tostring(a+b)
end

return M
