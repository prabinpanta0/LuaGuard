-- password_policy.lua
-- Checks if a password meets modern complexity requirements
local M = {}

function M.is_strong(password)
    if type(password) ~= 'string' then return false, 'Password must be a string' end
    if #password < 8 then return false, 'Password must be at least 8 characters' end
    if not password:match('%l') then return false, 'Password must contain a lowercase letter' end
    if not password:match('%u') then return false, 'Password must contain an uppercase letter' end
    if not password:match('%d') then return false, 'Password must contain a number' end
    if not password:match('[%p]') then return false, 'Password must contain a punctuation/special character' end
    return true
end

return M
