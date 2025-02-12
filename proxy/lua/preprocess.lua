local helper = require "helper"
local templates = require "templates"
package.path = package.path .. ";./?.lua"
local file_path = "/var/www/hosts/hosts.json"

local function entrypoint()
    local get_data = ngx.req.get_uri_args()
    local headers = ngx.req.get_headers()
    local post_data = nil

    local client_ip = ngx.var.http_cf_connecting_ip or ngx.var.http_x_forwarded_for or ngx.var.remote_addr or "127.0.0.1"
    ngx.var.client_ip = client_ip

    ngx.ctx.request_id = helper.generate_uuid()
    local host = ngx.var.host
    if not host then
        ngx.log(ngx.ERR, "No host header found")
        helper.render_forbidden("No host header found")
        return
    end

    local root_domain, subdomain = helper.get_domain_and_subdomain(host)
    local domain = nil
    if not root_domain then
        ngx.log(ngx.ERR, "Failed to extract root domain from host: ", host)
        helper.render_failed()
        return
    end
    domain = root_domain
    if subdomain then
        domain = subdomain .. "." .. domain
    end

    local proxy_dest = helper.get_proxy_dest(domain, file_path)
    if not proxy_dest then
        ngx.log(ngx.ERR, "No proxy destination found for domain: ", domain)
        helper.render_failed()
        return
    end

    local uri = ngx.var.uri
    ngx.var.backend = "http://" .. proxy_dest .. uri
    if ngx.var.is_args ~= nil and ngx.var.args ~= nil then
        ngx.var.backend = ngx.var.backend .. ngx.var.is_args .. ngx.var.args
    end

    ngx.log(ngx.ERR, "Proxying to: ", ngx.var.backend)

    if string.match(uri, "%.css$") or 
        string.match(uri, "%.js$") or 
        string.match(uri, "%.png$") or
        string.match(uri, "%.jpg$") or 
        string.match(uri, "%.jpeg$") or 
        string.match(uri, "%.ico$") or 
        string.match(uri, "%.map$") or 
        string.match(uri, "%.gif$") or 
        string.match(uri, "%.woff$") or 
        string.match(uri, "%.woff2$") or 
        string.match(uri, "%.ttf$") or 
        string.match(uri, "%.eot$") or 
        string.match(uri, "%.otf$") or 
        string.match(uri, "%.svg$") or 
        string.match(uri, "%.mp4$") or 
        string.match(uri, "%.webm$") or 
        string.match(uri, "%.ogv$") or 
        string.match(uri, "%.mp3$") or 
        string.match(uri, "%.ogg$") or 
        string.match(uri, "%.wav$") or 
        string.match(uri, "%.bmp$") or 
        string.match(uri, "%.tiff$") or 
        string.match(uri, "%.webp$") then
        ngx.var.cache_key = proxy_dest .. uri
        return ngx.exec("@proxycache")
    end

    return ngx.exec("@proxy")
end

entrypoint()