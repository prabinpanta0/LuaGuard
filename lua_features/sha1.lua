-- Minimal SHA1 implementation in pure Lua
local M = {}
-- ...for brevity, use a placeholder. In production, use a vetted implementation...
function M.sum(msg)
  -- This is a stub. Use a real SHA1 implementation for production.
  return string.rep('\0', 20)
end
return M
