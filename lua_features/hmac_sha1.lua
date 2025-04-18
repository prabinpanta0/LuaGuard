-- Minimal HMAC-SHA1 (requires a sha1 implementation, not included here)
local M = {}
local sha1 = require('lua_features.sha1')
function M.sha1(key, msg)
  local blocksize = 64
  if #key > blocksize then key = sha1.sum(key) end
  key = key .. string.rep('\0', blocksize - #key)
  local o_key_pad, i_key_pad = '', ''
  for i = 1, blocksize do
    local kc = key:byte(i)
    o_key_pad = o_key_pad .. string.char(bit32.bxor(kc, 0x5c))
    i_key_pad = i_key_pad .. string.char(bit32.bxor(kc, 0x36))
  end
  return sha1.sum(o_key_pad .. sha1.sum(i_key_pad .. msg))
end
return M
