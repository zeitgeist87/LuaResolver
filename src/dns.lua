-- LuaDNS - A simple DNS resolver written in Lua
-- Copyright (C) 2014 Andreas Rohner
-- 
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Lesser General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
-- 
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU Lesser General Public License for more details.
-- 
-- You should have received a copy of the GNU Lesser General Public License
-- along with this program. If not, see <http://www.gnu.org/licenses/>.

--- ---------------------------------------------------------------------------
-- A simple DNS resolver written in Lua. It doesn't need bit operations
-- and is therefore compatible with Lua5.1, Lua5.2 and LuaJIT. The
-- only dependency is LuaSocket.
-- 
-- @module Dns
-- ----------------------------------------------------------------------------

local socket = require "socket"

local defaultServers = {
	"213.73.91.35", -- (dnscache.berlin.ccc.de)
	"85.214.20.141", -- (FoeBud)
	"204.152.184.76", -- (f.6to4-servers.net, ISC, USA)
	"2001:4f8:0:2::14", -- (f.6to4-servers.net, IPv6, ISC)
	"194.150.168.168", -- (dns.as250.net; anycast DNS!)
}

local Dns = {}

local recordTypes = {
	A = 1,
	AAAA = 28,-- IPv6
	NS = 2,
	CNAME = 5,
	SOA = 6,
	PTR = 12,
	MX = 15, -- Mail exchange (MX) record
	TXT = 16,
	["*"] = 255
}

recordTypes[1] = "A"
recordTypes[28] = "AAAA"
recordTypes[2] = "NS"
recordTypes[5] = "CNAME"
recordTypes[6] = "SOA"
recordTypes[12] = "PTR"
recordTypes[15] = "MX"
recordTypes[16] = "TXT"
recordTypes[255] = "*"

local classTypes = {
	IN = 1, -- the Internet
	CS = 2, -- the CSNET class (Obsolete)
	CH = 3, -- the CHAOS class
	HS = 4, -- Hesiod [Dyer 87]
	["*"] = 255
}

classTypes[1] = "IN"
classTypes[2] = "CS"
classTypes[3] = "CH"
classTypes[4] = "HS"
classTypes[255] = "*"

local transId = 0
local function getTransId()
	if transId > 65535 then
		transId = 0
	end
	transId = transId + 1
	return transId
end

local dnsCache = {}

--- ---------------------------------------------------------------------------
-- Should be called periodically to cleanup the internal DNS Cache
-- ----------------------------------------------------------------------------
function Dns.cleanup()
	for _, v in pairs(dnsCache) do
		for domain, recs in pairs(v) do
			for i, rec in ipairs(recs) do
				if os.time() > rec.header.timeout then
					v[domain] = nil
					break
				end
			end
		end
	end
end

local function parseShort(b1, b2)
	local n = b1 + b2 * 256
	return n
end

local function parseInt(b1, b2, b3, b4)
	local n = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
	return n
end

local maxRecursionDepth = 5
local function parseDomainName(buf, i, str)
	if not str then
		str = ""
		maxRecursionDepth = 5
	end

	maxRecursionDepth = maxRecursionDepth - 1
	if maxRecursionDepth == 0 then
		error("Recursion too deep")
	end

	while buf:byte(i) ~= 0 and buf:byte(i) < 64 do
		local count = buf:byte(i)

		str = str .. buf:sub(i + 1, i + count) .. "."
		i = i + count + 1
	end

	if buf:byte(i) == 0 then
		i = i + 1
		str = str:sub(1, -2)
	elseif buf:byte(i) >= 192 then
		-- if first two bits are 1 then its a pointer (dns compression)
		local i2 = parseShort(buf:byte(i + 1), buf:byte(i) % 192) + 1

		str = parseDomainName(buf, i2, str)
		i = i + 2
	end

	return str, i
end

local function parseRecordData(buf, i, type, len)
	if type == "A" then
		local byte1, byte2, byte3, byte4 = buf:byte(i, i + 4)
		return tostring(byte1) .. "." .. byte2 .. "." .. byte3 .. "." .. byte4
	elseif type == "AAAA" then
		local byte1, byte2, byte3, byte4,
			byte5, byte6, byte7, byte8,
			byte9, byte10, byte11, byte12,
			byte13, byte14, byte15, byte16 = buf:byte(i, i + 16)
		local short1 = parseShort(byte2, byte1)
		local short2 = parseShort(byte4, byte3);
		local short3 = parseShort(byte6, byte5);
		local short4 = parseShort(byte8, byte7);
		local short5 = parseShort(byte10, byte9);
		local short6 = parseShort(byte12, byte11);
		local short7 = parseShort(byte14, byte13);
		local short8 = parseShort(byte16, byte15);

		local out = string.format("%x:%x:%x:%x:%x:%x:%x:%x", short1, short2,
			short3, short4, short5, short6, short7, short8)
		local longestMatch = ""
		for m in out:gmatch("[0:]+") do
			if m:len() > longestMatch:len() then
				longestMatch = m
			end
		end

		if longestMatch == "" then
			return out;
		end

		return out:gsub(longestMatch, "::", 1)
	elseif type == "NS" or type == "CNAME" or type == "PTR" then
		return parseDomainName(buf, i)
	elseif type == "TXT" then
		local str = ""
		local stop = i + len

		while buf:byte(i) ~= 0 and i < stop do
			local count = buf:byte(i)

			str = str .. buf:sub(i + 1, i + count)
			i = i + count + 1
		end
		return str
	elseif type == "SOA" then
		local mname, rname
		mname, i = parseDomainName(buf, i)
		rname, i = parseDomainName(buf, i)
		
		local byte1, byte2, byte3, byte4,
			byte5, byte6, byte7, byte8,
			byte9, byte10, byte11, byte12,
			byte13, byte14, byte15, byte16,
			byte17, byte18, byte19, byte20 = buf:byte(i, i + 20)
		local serial = parseInt(byte4, byte3, byte2, byte1)
		local refresh = parseInt(byte8, byte7, byte6, byte5)
		local retry = parseInt(byte12, byte11, byte10, byte9)
		local expire = parseInt(byte16, byte15, byte14, byte13)
		local minimum = parseInt(byte20, byte19, byte18, byte17)
		
		return {
			mname = mname,
			rname = rname,
			serial = serial,
			refresh = refresh,
			retry = retry,
			expire = expire,
			minimum = minimum
		}
	elseif type == "MX" then
		local priority = parseShort(buf:byte(i + 1), buf:byte(i))
		local domain = parseDomainName(buf, i + 2)
		if domain then
			return {priority = priority, name = domain}
		end
	end
	return nil
end

local function parseQuestionRecord(buf, i, results)
	local domain
	domain, i = parseDomainName(buf, i)

	local type = recordTypes[parseShort(buf:byte(i + 1), buf:byte(i))]
	i = i + 2
	local class = classTypes[parseShort(buf:byte(i + 1), buf:byte(i))]
	i = i + 2

	results[#results + 1] = {
		name = domain,
		type = type,
		class = class
	}

	return i
end

local function parseResourceRecord(buf, i, results)
	local domain
	domain, i = parseDomainName(buf, i)

	local type = parseShort(buf:byte(i + 1), buf:byte(i))
	i = i + 2
	local class = parseShort(buf:byte(i + 1), buf:byte(i))
	i = i + 2

	local ttl = parseInt(buf:byte(i + 3), buf:byte(i + 2),
						 buf:byte(i + 1), buf:byte(i))
	i = i + 4

	local resourceLen = parseShort(buf:byte(i + 1), buf:byte(i))
	i = i + 2

	local data = parseRecordData(buf, i, recordTypes[type], resourceLen)
	local rawdata = buf:sub(i, i + resourceLen - 1)
	i = i + resourceLen

	results[#results + 1] = {
		name = domain,
		type = recordTypes[type] or "UNKOWN(" .. type .. ")",
		class = classTypes[class] or "UNKOWN(" .. class .. ")",
		ttl = ttl,
		timeout = os.time() + ttl,
		content = data,
		rawdata = rawdata
	}

	return i
end

local function parseResourceRecords(buf, i, results, count, minTtl)
	for v = 1, count do
		local succ, v = pcall(parseResourceRecord, buf, i, results)
		if not succ then
			if v:find(":") then
				v = "Invalid record format"
			end
			return nil, nil, v
		end
		i = v

		local ttl = results[#results].ttl
		if ttl < minTtl then
			minTtl = ttl
		end
	end
	
	return i, minTtl
end

local function parseResponse(buf)
	if buf:len() < 12 then
		return nil, "Invalid record format"
	end

	local record = {
		header = {
			id = nil,
			flags = {
				query = false,
				truncated = false,
				authoritativeAnswer = false,
				recursionDesired = false,
				recursionAvailable = false,
			},
			opCode = 0,
			resCode = 0,
			ttl = 0,
			timeout = 0,
		},
		questions = {},
		answers = {},
		nameservers = {},
		additionals = {},
	}

	local h = record.header

	-- interpret result
	-- read some bitfields out of the header
	h.id = parseShort(buf:byte(2), buf:byte(1))
	h.flags.query = math.floor(buf:byte(3) / 128) == 0
	h.flags.truncated = buf:byte(3) % 4 > 1
	h.flags.recursionDesired = buf:byte(3) % 2 == 1
	h.flags.authoritativeAnswer = buf:byte(3) % 8 > 3
	h.flags.recursionAvailable = math.floor(buf:byte(4) / 128) == 1
	h.resCode = buf:byte(4) % 128
	h.opCode = math.floor(buf:byte(3) / 8) % 16

	if h.resCode ~= 0 then
		return record
	end

	local questionCount = parseShort(buf:byte(6), buf:byte(5))
	local answerCount = parseShort(buf:byte(8), buf:byte(7))
	local authorityCount = parseShort(buf:byte(10), buf:byte(9))
	local additionalCount = parseShort(buf:byte(12), buf:byte(11))

	local i = 13
	local minTtl = 7 * 24 * 60 * 60
	local errmsg

	for v= 1, questionCount do
		local succ, v = pcall(parseQuestionRecord, buf, i, record.questions)
		if not succ then
			if v:find(":") then
				v = "Invalid record format"
			end
			return nil, v
		end
		i = v
	end
	
	i, minTtl, errmsg = parseResourceRecords(buf, i, record.answers,
											 answerCount, minTtl)
	if errmsg then
		return nil, errmsg
	end
	
	i, minTtl, errmsg = parseResourceRecords(buf, i, record.nameservers,
											 authorityCount, minTtl)
	if errmsg then
		return nil, errmsg
	end
	
	i, minTtl, errmsg = parseResourceRecords(buf, i, record.additionals,
											 additionalCount, minTtl)
	if errmsg then
		return nil, errmsg
	end

	-- keep it for min 2 minute
	if minTtl < 120 then
		minTtl = 120
	end

	h.ttl = minTtl
	h.timeout = os.time() + minTtl;

	return record;
end

local function resolveSimple(domainName, recordType, server, timeout)
	if not recordTypes[recordType] then
		return nil, "Unkown record type (or not implemented)"
	end
	
	if dnsCache[recordType] and dnsCache[recordType][domainName] then
		local rec = dnsCache[recordType][domainName]

		if os.time() <= rec.header.timeout then
			return rec
		end
	end

	local currId = getTransId()

	-- 16bit = transaction id
	-- 8bit = some header bit fields
	--        (rightmost bit "recursion desired") set to 1 for recursion
	-- 8bit = some response headers set to 0 for query
	-- 16bit = query count normally only 1
	-- 3x16bit = response counts
	local query = string.char(math.floor(currId / 256), currId % 256, 1,
		0, 0, 1, 0, 0, 0, 0, 0, 0)

	for word in domainName:gmatch("%w+") do
		if word:len() > 63 then
			return nil, "Invalid domain: Labels are too long"
		end
		query = query .. string.char(word:len()) .. word
	end
	query = query .. string.char(0, 0, recordTypes[recordType], 0, 1)

	local s = socket.udp()
	if s then
		if s:setpeername(server, 53) then
			s:settimeout(timeout)
		end
	end

	if not s then
		return nil, "Unable to open socket"
	end

	s:send(query)
	local res, errmsg = s:receive()
	s:close()

	if not res then
		return nil, errmsg
	end

	local rec, errmsg = parseResponse(res)
	if not rec then
		return nil, errmsg
	end

	if rec.header.id ~= currId then
		return nil, "Mismatching transaction id"
	end

	if rec.header.resCode ~= 0 then
		return nil, "Server returned error " .. rec.header.resCode
	end

	dnsCache[recordType] = dnsCache[recordType] or {}
	dnsCache[recordType][domainName] = rec
	return rec
end

--- ---------------------------------------------------------------------------
-- resolveRaw() starts a DNS query for the specified domain name and record
-- type. It either uses a set of default servers or the servers provided
-- with the servers parameter. It returns a table with the parsed response
-- or an error message
-- 
-- @param domainName	domain to be resolved
-- @param recordType	type of record to be queried (defaults to "A")
-- @param timeout		connection timeout in seconds (defaults to 5)
-- @param servers		table of servers (can be nil)
-- @return parsed DNS response with complete header and all flags intact
-- @return errmsg
-- ----------------------------------------------------------------------------
function Dns.resolveRaw(domainName, recordType, timeout, servers)
	local rec, errmsg
	
	timeout = timeout or 5
	recordType = recordType or "A"
	servers = servers or defaultServers

	for _, server in ipairs(servers) do
		rec, errmsg = resolveSimple(domainName, recordType, server, timeout)

		if rec then
			return rec
		end
	end

	return nil, errmsg
end

--- ---------------------------------------------------------------------------
-- resolve() works exactly the same as resolveRaw(), but it flattens the
-- structure of the returned object and strips unnecessary data, like the
-- header. It returns a simple sorted list of resource records.
-- 
-- @param domainName	domain to be resolved
-- @param recordType	type of record to be queried (defaults to "A")
-- @param timeout		connection timeout in seconds (defaults to 5)
-- @param servers		table of servers (can be nil)
-- @return sorted list of resource records
-- @return errmsg
-- ----------------------------------------------------------------------------
function Dns.resolve(domainName, recordType, timeout, servers)
	local rec, errmsg = Dns.resolveRaw(domainName, recordType, servers, timeout)

	if rec then
		local tmp = {}
		local res = {}

		for _, r in ipairs(rec.answers) do
			tmp[#tmp + 1] = r
		end

		for _, r in ipairs(rec.nameservers) do
			tmp[#tmp + 1] = r
		end

		for _, r in ipairs(rec.additionals) do
			tmp[#tmp + 1] = r
		end

		for _, r in ipairs(tmp) do
			local newr = {
				name = r.name,
				type = r.type,
				class = r.class,
				content = r.content
			}
			if newr.type == "MX" then
				newr.priority = r.content.priority
				newr.content = r.content.name
			end

			if newr.type == "SOA" then
				local c = r.content
				newr.content = c.mname .. " " .. c.rname .. " " .. c.serial ..
							" " .. c.refresh .. " " ..  c.retry .. " " ..
							c.expire .. " " .. c.minimum
			end

			res[#res + 1] = newr
		end

		table.sort(res, function(a, b)
			if a.name < b.name then
				return true
			elseif a.name == b.name then
				if a.type < b.type then
					return true
				elseif a.type == b.type then
					if a.priority and b.priority and a.priority < b.priority then
						return true
					end
				end
			end
			return false
		end)

		return res
	end

	return nil, errmsg
end

return Dns
