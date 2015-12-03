LuaResolver
======

A simple DNS resolver written entirely in Lua. It doesn't need bit operations
and is therefore compatible with Lua5.1, Lua5.2 and LuaJIT. The
only dependency is LuaSocket.

## Usage

The `Resolver:resolve()` method returns a sorted table with resource records or nil and
an error message.

```lua
local Resolver = require "dns.resolver"
local r = Resolver.new({"213.73.91.35"}, 2)
r:addServer("85.214.20.141")

local recs, errmsg = r:resolve("google.com", "*")
if not errmsg then
    for _, v in ipairs(recs) do
        print(v.name, v.type, v.class, v.content)
    end
end
```

The `Resolver:resolveRaw()` method returns more data about the DNS response and also
includes the raw data of the resource records. The returned table looks
something like this:

```lua
resultOfResolveRaw = {
    header = {
        id,         -- transaction id
        flags = {
            query = false,              -- if this is a query
            truncated = false,          -- message was truncated
            authoritativeAnswer = false,
            recursionDesired = true,
            recursionAvailable = true,
        },
        opCode,
        errCode, -- error code
        ttl,     -- time to live in seconds
        timeout, -- os.time() + ttl
    },
    questions = {},   -- queries that were sent
    answers = {
        [1] = {
            name,
            type,
            class,
            ttl,
            timeout,
            content,
            rawdata
        }
    },                -- resource records
    authorities = {}, -- resource records for the authoritative ns
    additionals = {}, -- additional resource records
}
```

## Demo

The demo.lua script simply prints the resource records to stdout.

```
lua demo.lua google.com "*"
google.com	A	IN	173.194.112.103
google.com	A	IN	173.194.112.100
google.com	A	IN	173.194.112.101
google.com	A	IN	173.194.112.110
google.com	A	IN	173.194.112.105
google.com	A	IN	173.194.112.99
google.com	A	IN	173.194.112.104
google.com	A	IN	173.194.112.96
google.com	A	IN	173.194.112.98
google.com	A	IN	173.194.112.102
google.com	A	IN	173.194.112.97
google.com	AAAA	IN	2a00:1450:4001:803::1000
google.com	MX	IN	aspmx.l.google.com
google.com	MX	IN	alt1.aspmx.l.google.com
google.com	MX	IN	alt2.aspmx.l.google.com
google.com	MX	IN	alt3.aspmx.l.google.com
google.com	MX	IN	alt4.aspmx.l.google.com
google.com	NS	IN	ns1.google.com
google.com	NS	IN	ns4.google.com
google.com	NS	IN	ns2.google.com
google.com	NS	IN	ns3.google.com
google.com	TXT	IN	v=spf1 include:_spf.google.com ip4:216.73.93.70/31 ip4:216.73.93.72/31 ~all
```

## Documentation

new
-----
`syntax: r = Resolver.new(servers, timeout)`

Creates a new instance of `Resolver`.

* `servers`
	list of DNS servers
* `timeout`
	connection timeout

resolveRaw
-----
`syntax: resp, err = Resolver:resolveRaw(domainName, recordType)`

Starts a DNS query for the specified domain name and record
type. It iterates through the list of servers provided on instanciation or
through `addServer` and queries each one for the `domainName` and
`recordType` until one of them responds with a successful answer.
It returns a table with the parsed response or nil and an error message.


* `domainName`
	domain to be resolved
* `recordType`
	type of record to be queried (defaults to "A")

resolve
-----
`syntax: resp, err = Resolver:resolve(domainName, recordType)`

Works exactly the same as `resolveRaw`, but it flattens the
structure of the returned object and strips unnecessary data, like the
header. It returns a simple sorted list of resource records.

* `domainName`
	domain to be resolved
* `recordType`
	type of record to be queried (defaults to "A")


addServer
-----
`syntax: Resolver:addServer(server)`

Adds a DNS server to the list of servers

* `server`
	DNS server


enableTcp
-----
`syntax: Resolver:enableTcp()`

Enable tcp resolution


disableCache
-----
`syntax: Resolver:disableCache()`

Disable caching feature

cleanup
-----
`syntax: Resolver:cleanup()`

Should be called periodically to cleanup the internal DNS cache

## TODO

* Fall back to tcp when udp truncate
* Recursion parameter
* Support for more record types
