local M = {}

-- Helper: Read/write JSON DB
function M.read_db(path)
  local f = io.open(path, 'r')
  if not f then return {} end
  local data = f:read('*a')
  f:close()
  return require('dkjson').decode(data) or {}
end
function M.write_db(path, tbl)
  local f = io.open(path, 'w')
  f:write(require('dkjson').encode(tbl))
  f:close()
end

-- Helper: Generate random string
function M.random_string(len)
  local t = {}
  for i = 1, len do t[i] = string.char(math.random(33, 126)) end
  return table.concat(t)
end

-- Helper: Rate limiting
function M.check_rate_limit(ip, db_path)
  local rl = M.read_db(db_path)
  local now = os.time()
  rl[ip] = rl[ip] or {count=0, last=now}
  if now - rl[ip].last > 3600 then rl[ip] = {count=0, last=now} end
  rl[ip].count = rl[ip].count + 1
  rl[ip].last = now
  M.write_db(db_path, rl)
  return rl[ip].count <= 5
end

return M
