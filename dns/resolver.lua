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
-- A simple DNS resolver written in Lua. It doesn't need bit operations
-- and is therefore compatible with Lua5.1, Lua5.2 and LuaJIT. The
-- only dependency is LuaSocket.
-- 
-- @module Resolver

local socket = require "socket"
local Parser = require "dns.parser"

local Resolver = {}
Resolver.__index = Resolver

-------------------------------------------------------------------------------
-- Creates a new instance of `Resolver`.
-- 
-- @function [parent=#Resolver] new
-- @param #table servers	list of DNS servers
-- @param #number timeout	connection timeout
-- @return new instance of `Resolver`

function Resolver.new(servers, timeout)
	return setmetatable({servers = servers or {}, cache = {}, timeout = timeout or 5}, Resolver)
end

-------------------------------------------------------------------------------
-- Adds a DNS server to the list of servers
-- 
-- @function [parent=#Resolver] addServer
-- @param #string server	DNS server

function Resolver:addServer(server)
	local servers = self.servers
	servers[#servers + 1] = server
end

local transId = 0
local function getTransId()
	if transId > 65535 then
		transId = 0
	end
	transId = transId + 1
	return transId
end

-------------------------------------------------------------------------------
-- Should be called periodically to cleanup the internal DNS cache
-- @function [parent=#Resolver] cleanup

function Resolver:cleanup()
	for _, types in pairs(self.cache) do
		for type, rec in pairs(types) do
			if os.time() > rec.header.timeout then
				types[type] = nil
				break
			end
		end
	end
end

function Resolver:query(domainName, recordType, server)
	if not Parser.recordTypes[recordType] then
		return nil, "Unkown record type (or not implemented)"
	end
	
	if self.cache[domainName] and self.cache[domainName][recordType] then
		local rec = self.cache[domainName][recordType]

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
	query = query .. string.char(0, 0, Parser.recordTypes[recordType], 0, 1)

	local s = socket.udp()
	if s then
		if s:setpeername(server, 53) then
			s:settimeout(self.timeout)
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
	
	local parser = Parser.new(res)

	local rec, errmsg = parser:parse()
	if not rec then
		return nil, errmsg
	end

	if rec.header.id ~= currId then
		return nil, "Mismatching transaction id"
	end

	if rec.header.errCode ~= 0 then
		return nil, "Server returned error " .. rec.header.errCode
	end

	self.cache[domainName] = self.cache[domainName] or {}
	self.cache[domainName][recordType] = rec
	return rec
end

-------------------------------------------------------------------------------
-- Starts a DNS query for the specified domain name and record
-- type. It iterates through the list of servers provided on instanciation or
-- through `addServer` and queries each one for the `domainName` and
-- `recordType` until one of them responds with a successful answer.
-- It returns a table with the parsed response or nil and an error message.
-- 
-- @function [parent=#Resolver] resolveRaw
-- @param #string domainName	domain to be resolved
-- @param #string recordType	type of record to be queried (defaults to "A")
-- @return #table parsed DNS response with complete header and all flags intact
-- @return #nil,#string errmsg

function Resolver:resolveRaw(domainName, recordType)
	local rec, errmsg
	recordType = recordType or "A"

	for _, server in ipairs(self.servers) do
		rec, errmsg = self:query(domainName, recordType, server)

		if rec then
			return rec
		end
	end

	return nil, errmsg
end

-------------------------------------------------------------------------------
-- Works exactly the same as `resolveRaw`, but it flattens the
-- structure of the returned object and strips unnecessary data, like the
-- header. It returns a simple sorted list of resource records.
-- 
-- @function [parent=#Resolver] resolve
-- @param #string domainName	domain to be resolved
-- @param #string recordType	type of record to be queried (defaults to "A")
-- @return #table sorted list of resource records
-- @return #nil,#string errmsg

function Resolver:resolve(domainName, recordType)
	local rec, errmsg = self:resolveRaw(domainName, recordType)

	if rec then
		local tmp = {}
		local res = {}

		for _, r in ipairs(rec.answers) do
			tmp[#tmp + 1] = r
		end

		for _, r in ipairs(rec.authorities) do
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

return Resolver
