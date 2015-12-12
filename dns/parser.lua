-- LuaResolver - A simple DNS resolver written in Lua
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

-------------------------------------------------------------------------------
-- A parser for DNS responses. It takes a string buffer of the DNS response
-- as input and returns a table with the parsed results.
--
-- @module Parser

local Parser = {}
Parser.__index = Parser

local recordTypes = {
	A = 1,
	AAAA = 28,-- IPv6
	NS = 2,
	CNAME = 5,
	SOA = 6,
	PTR = 12,
	MX = 15, -- Mail exchange (MX) record
	TXT = 16,
	["*"] = 255,
	AFSDB = 18,
	APL = 42,
	CAA = 257,
	CERT = 37,
	DHCID = 49,
	DLV = 32769,
	DNAME = 39,
	DNSKEY = 48,
	DS = 43,
	HIP = 55,
	IPSECKEY = 45,
	KEY = 25,
	KX = 36,
	LOC = 29,
	NAPTR = 35,
	NSEC = 47,
	NSEC3 = 50,
	NSEC3PARAM = 51,
	RRSIG = 46,
	RP = 17,
	SIG = 24,
	SPF = 99,
	SRV = 33,
	SSHFP = 44,
	TA = 32768,
	TKEY = 249,
	TLSA = 52,
	TSIG = 250,
}

local classTypes = {
	IN = 1, -- the Internet
	CS = 2, -- the CSNET class (Obsolete)
	CH = 3, -- the CHAOS class
	HS = 4, -- Hesiod [Dyer 87]
	["*"] = 255,
}

local function reverseMapping(map)
	local reverse = {}
	for k, v in pairs(map) do
		reverse[v] = k
	end
	for k, v in pairs(reverse) do
		map[k] = v
	end
end

reverseMapping(recordTypes)
reverseMapping(classTypes)

Parser.recordTypes = recordTypes
Parser.classTypes = classTypes

-------------------------------------------------------------------------------
-- Creates a new instance of Parser.
--
-- @function [parent=#Parser] new
-- @param #string buf	a buffer containing the response from a DNS server
-- @return new instance of Parser

function Parser.new(buf)
	return setmetatable({buf = buf, pos = 1, minTtl = 7 * 24 * 60 * 60}, Parser)
end

function Parser:parseShort()
	local pos = self.pos
	local b2, b1 = self.buf:byte(pos, pos + 1)
	pos = pos + 2
	self.pos = pos
	
	return b1 + b2 * 256
end

function Parser:parsePointer(pos)
	local b2, b1 = self.buf:byte(pos, pos + 1)
	return b1 + ((b2 % 192) * 256) + 1
end

function Parser:parseInt()
	local pos = self.pos
	local b4, b3, b2, b1 = self.buf:byte(pos, pos + 3)
	pos = pos + 4
	self.pos = pos
	
	return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
end

function Parser:parseDomainName(str, pos)
	if not str then
		str = ""
		self.maxRecDepth = 5
	end

	self.maxRecDepth = self.maxRecDepth - 1
	if self.maxRecDepth == 0 then
		error("Recursion too deep")
	end
	
	local buf = self.buf
	pos = pos or self.pos
	local count = buf:byte(pos)

	while count ~= 0 and count < 64 do
		str = str .. buf:sub(pos + 1, pos + count) .. "."
		
		pos = pos + count + 1
		count = buf:byte(pos)
	end

	if count == 0 then
		pos = pos + 1
		--remove the last .
		str = str:sub(1, -2)
	elseif count >= 192 then
		-- if first two bits are 1 then its a pointer (dns compression)
		local pos2 = self:parsePointer(pos)
		pos = pos + 2

		str = self:parseDomainName(str, pos2)
	end

	self.pos = pos
	return str
end

function Parser:parseA()
	local pos = self.pos
	local buf = self.buf
	local byte1, byte2, byte3, byte4 = buf:byte(pos, pos + 3)

	return tostring(byte1) .. "." .. byte2 .. "." .. byte3 .. "." .. byte4
end

function Parser:parseAAAA()
	local short1 = self:parseShort()
	local short2 = self:parseShort();
	local short3 = self:parseShort();
	local short4 = self:parseShort();
	local short5 = self:parseShort();
	local short6 = self:parseShort();
	local short7 = self:parseShort();
	local short8 = self:parseShort();

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
end

function Parser:parseNS()
	return self:parseDomainName()
end

Parser.parseCNAME = Parser.parseNS
Parser.parsePTR = Parser.parseNS

function Parser:parseTXT(len)
	local pos = self.pos
	local buf = self.buf
	local str = ""
	local stop = pos + len
	local count = buf:byte(pos)

	while count ~= 0 and pos < stop do
		str = str .. buf:sub(pos + 1, pos + count)
		pos = pos + count + 1
		
		count = buf:byte(pos)
	end
	return str
end

function Parser:parseSOA()
	local mname = self:parseDomainName()
	local rname = self:parseDomainName()
	local serial = self:parseInt()
	local refresh = self:parseInt()
	local retry = self:parseInt()
	local expire = self:parseInt()
	local minimum = self:parseInt()
	
	return {
		mname = mname,
		rname = rname,
		serial = serial,
		refresh = refresh,
		retry = retry,
		expire = expire,
		minimum = minimum
	}
end

function Parser:parseMX()
	local priority = self:parseShort()
	local domain = self:parseDomainName()

	return {priority = priority, name = domain}
end

function Parser:parseRecordData(type, len)
	local value
	local pos = self.pos
	
	if type then
		local m = self["parse" .. type]
		if m then
			value = m(self, len)
		end
	end
	
	self.pos = pos + len
	return value
end

function Parser:parseQuestion()
	local domain = self:parseDomainName()
	local type = recordTypes[self:parseShort()]
	local class = classTypes[self:parseShort()]

	return {
		name = domain,
		type = type,
		class = class
	}
end

function Parser:parseAnswer()
	local domain = self:parseDomainName()
	local type = self:parseShort()
	local class = self:parseShort()
	local ttl = self:parseInt()
	local resourceLen = self:parseShort()
	local rawdata = self.buf:sub(self.pos, self.pos + resourceLen - 1)
	local data = self:parseRecordData(recordTypes[type], resourceLen)

	return {
		name = domain,
		type = recordTypes[type] or "UNKOWN(" .. type .. ")",
		class = classTypes[class] or "UNKOWN(" .. class .. ")",
		ttl = ttl,
		timeout = os.time() + ttl,
		content = data,
		rawdata = rawdata
	}
end

function Parser:parseRRs(func, count)
	local results = {}
	
	for i = 1, count do
		local succ, v = pcall(func, self)
		if not succ then
			if v:find(":") then
				v = "Invalid record format"
			end
			return nil, v
		end

		local ttl = v.ttl
		if ttl and ttl < self.minTtl then
			self.minTtl = ttl
		end
		
		results[#results + 1] = v
	end
	
	return results
end

function Parser:parseHeader()
	local buf = self.buf
	local pos = self.pos
	local b3 = buf:byte(pos + 2)
	local b4 = buf:byte(pos + 3)
	local h = {flags = {}}

	h.id = self:parseShort()
	h.flags.query = math.floor(b3 / 128) == 0
	h.flags.truncated = b3 % 4 > 1
	h.flags.recursionDesired = b3 % 2 == 1
	h.flags.authoritativeAnswer = b3 % 8 > 3
	h.flags.recursionAvailable = math.floor(b4 / 128) == 1
	h.opCode = math.floor(b3 / 8) % 16
	h.errCode = b4 % 128
	
	self.pos = pos + 4
	return h
end

-------------------------------------------------------------------------------
-- Parses the input data and returns the result as a lua table
--
-- @function [parent=#Parser] parse
-- @param #string buf	a buffer containing the response from a DNS server
-- @return #table		parsed result

function Parser:parse()
	local buf = self.buf
	if buf:len() < 12 then
		return nil, "Invalid record format"
	end

	local result = {}
	result.header = self:parseHeader()

	if result.header.errCode ~= 0 then
		return result
	end

	local qc = self:parseShort()
	local ac = self:parseShort()
	local auc = self:parseShort()
	local adc = self:parseShort()

	local errmsg
	result.questions, errmsg = self:parseRRs(Parser.parseQuestion, qc)
	if errmsg then
		return nil, errmsg
	end
	
	result.answers, errmsg = self:parseRRs(Parser.parseAnswer, ac)
	if errmsg then
		return nil, errmsg
	end
	
	result.authorities, errmsg = self:parseRRs(Parser.parseAnswer, auc)
	if errmsg then
		return nil, errmsg
	end
	
	result.additionals, errmsg = self:parseRRs(Parser.parseAnswer, adc)
	if errmsg then
		return nil, errmsg
	end

	-- keep it for min 2 minute
	if self.minTtl < 120 then
		self.minTtl = 120
	end

	result.header.ttl = self.minTtl
	result.header.timeout = os.time() + self.minTtl;

	return result;
end

return Parser
