-- Minimal base32 decode (RFC 4648, A-Z2-7, no padding)
local M = {}
local b32 = {}
for i = 0, 25 do b32[string.char(65+i)] = i end
for i = 0, 5 do b32[tostring(i+2)] = i+26 end
function M.decode(s)
  local bits, val, out = 0, 0, {}
  for c in s:gmatch(".") do
    local v = b32[c]
    if v then
      val = val * 32 + v
      bits = bits + 5
      if bits >= 8 then
        bits = bits - 8
        table.insert(out, string.char(bit32.rshift(val, bits) % 256))
        val = val % (2^bits)
      end
    end
  end
  return table.concat(out)
end
return M
