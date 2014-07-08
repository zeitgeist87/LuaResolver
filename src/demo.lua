local dns = require "dns"

local function main(domain, type)
	type = type or "*"
	if not domain then
		print("Usage: ./demo.lua DOMAIN [RECORDTYPE]")
		return
	end
	
	local rec, errmsg = dns.resolve(domain, type)
	if errmsg then
		print(errmsg)
		return
	end

	for _, v in ipairs(rec) do
		print(v.name, v.type, v.class, v.content)
	end
end
main(arg[1], arg[2])
