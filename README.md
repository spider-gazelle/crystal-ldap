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
result = client.authenticate(user, pass).get

if result.tag.bind_result?
  result_code = result.parse_bind_response[:result_code]
  raise "bind failed with #{result_code}" unless result_code.success?
else
  client.close
  raise "unexpected response #{result.tag}"
end

# Can now perform LDAP operations
```

To use the non-standard `LDAPS` (LDAP Secure, commonly known as LDAP over SSL) protocol then pass in a `OpenSSL::SSL::Socket::Client` directly: `LDAP::Client.new(tls_socket)`
