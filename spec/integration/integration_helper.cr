{% skip_file unless flag?(:integration) %}
require "socket"
require "../spec_helper"

# Shared connection config + helpers for the integration suite. Only compiled
# under `-Dintegration`. Defaults match docker-compose.yml; override via ENV.
module Integration
  HOST     = ENV["INTEGRATION_LDAP_HOST"]? || "localhost"
  PORT     = (ENV["INTEGRATION_LDAP_PORT"]? || "1389").to_i
  BASE     = ENV["INTEGRATION_LDAP_BASE"]? || "dc=example,dc=org"
  ADMIN_DN = ENV["INTEGRATION_LDAP_ADMIN_DN"]? || "cn=admin,dc=example,dc=org"
  ADMIN_PW = ENV["INTEGRATION_LDAP_ADMIN_PW"]? || "adminpassword"

  # A fresh client on a real TCP socket (not yet bound).
  def self.client : LDAP::Client
    LDAP::Client.new(TCPSocket.new(HOST, PORT))
  end

  # A client already bound as the directory admin.
  def self.bound_admin : LDAP::Client
    c = client
    c.authenticate(ADMIN_DN, ADMIN_PW)
    c
  end
end
