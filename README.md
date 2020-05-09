# LDAP Support for Crystal Lang

[![Build Status](https://travis-ci.org/spider-gazelle/crystal-ldap.svg?branch=master)](https://travis-ci.org/spider-gazelle/crystal-ldap)

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
filter = LDAP::Request::Filter.equal("objectClass", "person")
client.search(base: "dc=example,dc=com", filter: filter, size: 6, attributes: ["hasSubordinates", "objectClass"])

# Note how filters can be combined and standard LDAP queries can be parsed
filter = (filter & LDAP::Request::Filter.equal("sn", "training")) | LDAP::Request::FilterParser.parse("(uid=einstein)")
client.search(base: "dc=example,dc=com", filter: filter)
```

To use the non-standard `LDAPS` (LDAP Secure, commonly known as LDAP over SSL) protocol then pass in a `OpenSSL::SSL::Socket::Client` directly: `LDAP::Client.new(tls_socket)`
