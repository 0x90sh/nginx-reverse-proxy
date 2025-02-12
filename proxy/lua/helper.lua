local ffi = require("ffi")
local cjson = require("cjson")
local templates = require("templates")
local lfs = require("lfs") 
local str = require("resty.string")

-- Function to extract the root domain and subdomain from a host
-- @param host: The full host name (e.g., 'sub.example.com')
-- @return: root_domain (e.g., 'example.com'), subdomain (e.g., 'sub')
local function get_domain_and_subdomain(host)
    local root_domain_pattern = "([%w%-]+%.[%w%.%-]+)$"
    local subdomain_pattern = "([%w%-]+)%.([%w%-]+%.[%w%.%-]+)$"

    local subdomain, root_domain = host:match(subdomain_pattern)
    if subdomain and root_domain then
        return root_domain, subdomain
    end

    local root_domain = host:match(root_domain_pattern)
    return root_domain, nil
end

-- Define C functions to get the current time in seconds and nanoseconds
ffi.cdef[[
    typedef long time_t;
    typedef struct timespec {
        time_t tv_sec;
        long tv_nsec;
    } timespec;

    int clock_gettime(int clk_id, struct timespec *tp);
]]

-- Function to get the current time in seconds and nanoseconds
-- @return: seconds and nanoseconds since the Epoch
local function get_nanoseconds()
    local CLOCK_REALTIME = 0
    local ts = ffi.new("struct timespec")
    ffi.C.clock_gettime(CLOCK_REALTIME, ts)
    return tonumber(ts.tv_sec), tonumber(ts.tv_nsec)
end

-- Function to generate a UUID
-- @return: A randomly generated UUID string
local function generate_uuid()
    local sec, nsec = get_nanoseconds()
    local seed = tonumber((sec * 1000003 + nsec) % 1000000007)
    math.randomseed(seed)
    local template = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
    return string.gsub(template, '[xy]', function (c)
        local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
        if c == 'y' then
            v = (v - 8) % 4 + 8
        end
        return string.format('%x', v)
    end)
end

-- Function to retrieve a cookie by name
-- @param name: The name of the cookie
-- @return: The value of the cookie or false if not found
local function get_cookie(name)
    local cookie_str = ngx.var.http_cookie
    if not cookie_str then
        return false
    end
    local pattern = name .. "=([^;]*)"
    local _, _, value = string.find(cookie_str, pattern)
    return value or false
end

-- Function to unset a cookie
-- @param cookie_name: The name of the cookie to unset
local function unset_cookie(cookie_name)
    local cookie_string = string.format("%s=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;", cookie_name)
    ngx.header["Set-Cookie"] = cookie_string
end

-- Function to set a cookie
-- @param name: The name of the cookie
-- @param value: The value to assign to the cookie
local function set_cookie(name, value)
    local expires = ngx.cookie_time(ngx.time() + 30 * 60)
    local cookie_string = string.format("%s=%s; Path=/; Expires=%s; HttpOnly", name, ngx.escape_uri(value), expires)
    ngx.header["Set-Cookie"] = cookie_string
end

-- Function to check if a string is a valid UUID
-- @param str: The string to validate
-- @return: True if the string is a valid UUID, false otherwise
local function isUUID(str)
    local uuidPattern = "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"
    return string.match(str:lower(), uuidPattern) ~= nil
end

-- Function to check if a string represents a number
-- @param value: The string to check
-- @return: True if the string can be converted to a number, false otherwise
local function is_number_string(value)
    return tonumber(value) ~= nil
end

-- Function to replace placeholders in a template string
-- @param template: The template string containing '%%s' placeholders
-- @param ...: Values to replace the placeholders
-- @return: The formatted string with placeholders replaced by provided values
local function replacePlaceholders(template, ...)
    local values = {...}
    local index = 1
    return template:gsub("%%%%s", function()
        local value = values[index]
        index = index + 1
        return value
    end)
end

-- Function to render a 403 Forbidden response
-- @param message: Optional custom message to display; defaults to a standard message if not provided
local function render_forbidden(message)
    if message == "" or not message then
        message = "Your request has been blocked."
    end
    local request_id = ngx.ctx.request_id
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html"
    ngx.say(string.format(templates.forbidden, message, request_id or "unknown"))
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- Function to render a 500 Internal Server Error response
local function render_failed()
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    local request_id = ngx.ctx.request_id
    ngx.header.content_type = "text/html"
    ngx.say(string.format(templates.failed, request_id or "unknown"))
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end

-- Function to load host mappings from a JSON file
-- @param file_path: The path to the JSON file containing host mappings
-- @return: A table representing the host mappings, or nil if an error occurs
local function load_host_mappings(file_path)
    local file = io.open(file_path, "r")
    if not file then
        ngx.log(ngx.ERR, "Failed to open host mappings file: ", file_path)
        return nil
    end

    local content = file:read("*a")
    file:close()

    local success, data = pcall(cjson.decode, content)
    if not success then
        ngx.log(ngx.ERR, "Failed to decode JSON from file: ", file_path)
        return nil
    end

    return data
end

local function populate_cache(file_path)
    local host_mappings = load_host_mappings(file_path)
    if not host_mappings then
        return false
    end

    local host_cache = ngx.shared.host_cache
    host_cache:flush_all()

    for domain, proxy in pairs(host_mappings) do
        host_cache:set(domain, proxy)
    end

    host_cache:set("last_cache_update", ngx.time())

    return true
end

local function get_proxy_dest(root_domain, file_path)
    local host_cache = ngx.shared.host_cache
    local proxy_dest = host_cache:get(root_domain)

    if proxy_dest then
        return proxy_dest
    end

    local last_update = host_cache:get("last_cache_update")
    if not last_update or (ngx.time() - last_update) > 30 then
        local success = populate_cache(file_path)
        if not success then
            return nil
        end
        proxy_dest = host_cache:get(root_domain)
    end

    return proxy_dest
end

local function scan_patterns(data, patterns)
    for key, value in pairs(data) do
        for _, pattern in ipairs(patterns) do
            if type(key) == "string" and ngx.re.match(key, pattern, "ijo") then
                return true, key
            end
            if type(value) == "string" and ngx.re.match(value, pattern, "ijo") then
                return true, value
            end
        end
    end
    return false
end

-- Return the module's functions
return {
    generate_uuid = generate_uuid,
    get_cookie = get_cookie,
    unset_cookie = unset_cookie,
    set_cookie = set_cookie,
    isUUID = isUUID,
    is_number_string = is_number_string,
    replacePlaceholders = replacePlaceholders,
    get_domain_and_subdomain = get_domain_and_subdomain,
    render_failed = render_failed,
    render_forbidden = render_forbidden,
    get_proxy_dest = get_proxy_dest,
    scan_patterns = scan_patterns
}
