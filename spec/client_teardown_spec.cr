require "./spec_helper"
require "log/spec"

# Reproduces the teardown path behind issue #2: a failed simple bind.
#
# The server returns a BindResponse with a failure code; `#authenticate` raises
# and (in its rescue) closes the socket while the read fiber is parked inside
# `read_bytes` waiting for the next message. On a real socket that close tears
# the in-flight decode and surfaces as a *non*-`IO::Error` — which used to fall
# into `process!`'s generic `rescue e` and be logged at `:error`. At process
# exit that error log hit an already-closed `Log` dispatcher channel, producing
# the `Channel::ClosedError` mbab reported.
#
# This fake models exactly that: the first read returns the scripted bind
# failure; the next read parks until `close`, then raises a non-IO error.
class TornBindSocket < IO
  getter? closed = false

  def initialize(&@responder : Int32 -> Bytes)
    @sent = IO::Memory.new
    @incoming = IO::Memory.new
    @request_sent = Channel(Nil).new(1)
    @torn = Channel(Nil).new(1)
    @reads_opened = false
  end

  def read(slice : Bytes) : Int32
    unless @reads_opened
      @reads_opened = true
      @request_sent.receive
    end
    read = @incoming.read(slice)
    return read if read > 0
    # Scripted bytes exhausted: park like a socket waiting for more data, until
    # the connection is torn down, then fail mid-decode as the wire would.
    @torn.receive
    raise LDAP::Error.new("connection reset during read")
  end

  def write(slice : Bytes) : Nil
    @sent.write(slice)
  end

  def flush
    if @incoming.size.zero?
      message_id = IO::Memory.new(@sent.to_slice).read_bytes(ASN1::BER).children[0].get_integer.to_i
      @incoming.write @responder.call(message_id)
      @incoming.rewind
      @request_sent.send(nil)
    end
    self
  end

  def close
    @closed = true
    @torn.send(nil)
  end
end

private def bind_response(id : Int32, code : Int32)
  op = LDAP.app_sequence({
    LDAP::BER.new.set_integer(code, LDAP::UniversalTags::Enumerated),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
    LDAP::BER.new.set_string("Simple Bind Failed", LDAP::UniversalTags::OctetString),
  }, LDAP::Tag::BindResult)
  LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
end

describe LDAP::Client do
  describe "#authenticate" do
    it "raises AuthError on a failed bind" do
      invalid_credentials = LDAP::Response::Code::InvalidCredentials.value
      socket = TornBindSocket.new { |id| bind_response(id, invalid_credentials) }
      client = LDAP::Client.new(socket)

      expect_raises(LDAP::Client::AuthError, /InvalidCredentials/) do
        client.authenticate("cn=admin", "wrong-password")
      end
    end

    # Regression for #2: tearing the connection down after a failed bind must
    # not be logged as an error (it is an expected, deliberate close) — that
    # error log is what crashed at shutdown via the Log dispatcher channel.
    it "does not log an error when the read fiber is torn down by the close" do
      invalid_credentials = LDAP::Response::Code::InvalidCredentials.value
      logs = Log.capture("ldap") do
        socket = TornBindSocket.new { |id| bind_response(id, invalid_credentials) }
        client = LDAP::Client.new(socket)
        expect_raises(LDAP::Client::AuthError) do
          client.authenticate("cn=admin", "wrong-password")
        end
        # let the read fiber resume, hit the torn read, and run its rescue
        5.times { Fiber.yield }
      end

      logs.empty
    end
  end
end
