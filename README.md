# LDAP Support for Crystal Lang

[![CI](https://github.com/spider-gazelle/crystal-ldap/actions/workflows/ci.yml/badge.svg)](https://github.com/spider-gazelle/crystal-ldap/actions/workflows/ci.yml)

## Installation

Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     ldap:
       github: spider-gazelle/crystal-ldap
   ```

## Usage

### Connecting and Binding

Passing a TLS context will upgrade the connection using [start tls](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol#StartTLS)

```crystal
require "ldap"

host = "ldap.forumsys.com"
port = 389
user = "cn=read-only-admin,dc=example,dc=com"
pass = "password"

# Standard LDAP port with unencrypted socket
socket = TCPSocket.new(host, port)

# Providing a context will upgrade to encrypted comms using start tls (official method)
tls = OpenSSL::SSL::Context::Client.new
tls.verify_mode = OpenSSL::SSL::VerifyMode::NONE

# Bind to the server
client = LDAP::Client.new(socket, tls)
client.authenticate(user, pass)

# Can now perform LDAP operations
```

To use the non-standard `LDAPS` (LDAP Secure, commonly known as LDAP over SSL) protocol then pass in a `OpenSSL::SSL::Socket::Client` directly: `LDAP::Client.new(tls_socket)`

```crystal
# LDAPS method
socket = TCPSocket.new(host, port)
tls = OpenSSL::SSL::Context::Client.new
tls.verify_mode = OpenSSL::SSL::VerifyMode::NONE
socket = OpenSSL::SSL::Socket::Client.new(socket, context: tls, sync_close: true, hostname: host)

# Bind to the server
client = LDAP::Client.new(socket)
client.authenticate(user, pass)

# Can now perform LDAP operations
```


### Querying

You can perform search requests

```crystal

# You can use LDAP string filters directly
client.search(base: "dc=example,dc=com", filter: "(|(uid=einstein)(uid=training))")

# There are options to select particular attributes and limit response sizes
filter = LDAP::Request::Filter.equal("objectClass", "person")
client.search(
  base: "dc=example,dc=com",
  filter: filter,
  size: 6,
  attributes: ["hasSubordinates", "objectClass"]
)

# Filters can be combined using standard operations
filter = (
          LDAP::Request::Filter.equal("objectClass", "person") &
          LDAP::Request::Filter.equal("sn", "training")) |
          LDAP::Request::FilterParser.parse("(uid=einstein)"
         )
client.search(base: "dc=example,dc=com", filter: filter)

```

Search responses are `Array(Hash(String, Array(String)))`

```crystal

[
 {
  "dn" => ["uid=einstein,dc=example,dc=com"],
  "objectClass" => ["inetOrgPerson", "organizationalPerson", "person", "top"],
  "cn" => ["Albert Einstein"],
  "sn" => ["Einstein"],
  "uid" => ["einstein"],
  "mail" => ["einstein@ldap.forumsys.com"],
  "telephoneNumber" => ["314-159-2653"]
 },
 {
  "dn" => ["uid=training,dc=example,dc=com"],
  "uid" => ["training"],
  "objectClass" => ["inetOrgPerson", "organizationalPerson", "person", "top"],
  "cn" => ["FS Training"],
  "sn" => ["training"],
  "mail" => ["training@forumsys.com"],
  "telephoneNumber" => ["888-111-2222"]
 }
]

```
