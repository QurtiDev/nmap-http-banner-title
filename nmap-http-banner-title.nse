-- TITLE: HTTP Banner & Title Grabber
description = [[
  Quick check for open HTTP ports.
  Takes the "Server" header and grabs the title from the page.
]]
author = "Purpleware"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "quick"}

-- IMPORTS
local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"


-- RULES: Run on common HTTP ports
portrule = shortport.port_or_service({80, 8080, 8000, 8888}, "http")

-- ACTION
action = function(host, port)
  local out = {}

  -- Simple GET request
  local resp = http.get(host, port, "/")
  if not resp then return nil end

  -- Grab banner (Server header in this case)
  local banner = resp.header and resp.header.server
  if banner then
    table.insert(out, "Server: " .. banner)
  end

  -- Grab title
  if resp.body then
    local title = resp.body:match("<title>(.-)</title>")
    if title then
      table.insert(out, "Title: " .. title)
    end
  end

  if #out > 0 then
    return stdnse.format_output(true, out)
  else
    return "HTTP service detected (no banner/title found)"
  end
end
