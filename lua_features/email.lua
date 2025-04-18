local http = require('socket.http')
local ltn12 = require('ltn12')
local json = require('dkjson')

local M = {}

function M.send_verification_email(to, subject, body)
  local req_body = json.encode({to = to, subject = subject, body = body})
  local resp_body = {}
  http.request{
    url = 'http://127.0.0.1:8081/email',
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
  return data and data.success
end

return M
