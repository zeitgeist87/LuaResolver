local Resolver = require "dns.resolver"

local function main(domain, type)
	type = type or "*"
	if not domain then
		print("Usage: ./demo.lua DOMAIN [RECORDTYPE]")
		return
	end
	
	local r = Resolver.new({"213.73.91.35"}, 2)
	r:addServer("85.214.20.141")
	
	local rec, errmsg = r:resolve(domain, type)
	if errmsg then
		print(errmsg)
		return
	end

	for _, v in ipairs(rec) do
		print(v.name, v.type, v.class, v.content)
	end
end
main(arg[1], arg[2])
