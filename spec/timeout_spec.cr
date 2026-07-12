require "./spec_helper"

# A socket that accepts writes but never produces a response — its read blocks
# until the connection is closed. Models a hung/unresponsive server.
class SilentSocket < IO
  getter? closed = false

  def initialize
    @gate = Channel(Nil).new
  end

  def read(slice : Bytes) : Int32
    @gate.receive
    0
  end

  def write(slice : Bytes) : Nil
  end

  def flush
    self
  end

  def close
    return if @closed
    @closed = true
    @gate.close
  end
end

# Delivers a scripted response, then blocks its read (like a server that streamed
# some entries and then stalled without sending SearchResultDone).
class HangingSocket < IO
  getter? closed = false

  def initialize(&@responder : Int32 -> Bytes)
    @sent = IO::Memory.new
    @incoming = IO::Memory.new
    @request_sent = Channel(Nil).new(1)
    @gate = Channel(Nil).new
    @opened = false
  end

  def read(slice : Bytes) : Int32
    unless @opened
      @opened = true
      @request_sent.receive
    end
    read = @incoming.read(slice)
    return read if read > 0
    @gate.receive # scripted bytes exhausted: hang until close
    0
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
    return if @closed
    @closed = true
    @gate.close
  end
end

private def search_entry(id : Int32) : Bytes
  op = LDAP.app_sequence({
    LDAP::BER.new.set_string("uid=a,dc=x", LDAP::UniversalTags::OctetString),
    LDAP.sequence([] of LDAP::BER),
  }, LDAP::Tag::SearchReturnedData)
  LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
end

private def bind_success(id : Int32) : Bytes
  op = LDAP.app_sequence({
    LDAP::BER.new.set_integer(0, LDAP::UniversalTags::Enumerated),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
  }, LDAP::Tag::BindResult)
  LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
end

describe LDAP::Client do
  describe "timeout" do
    it "raises TimeoutError when an operation gets no response in time" do
      client = LDAP::Client.new(SilentSocket.new, timeout: 20.milliseconds)

      expect_raises(LDAP::Client::TimeoutError) do
        client.authenticate("cn=admin", "secret")
      end
    end

    it "raises TimeoutError on a compare that gets no response in time" do
      client = LDAP::Client.new(SilentSocket.new, timeout: 20.milliseconds)

      expect_raises(LDAP::Client::TimeoutError) do
        client.compare("uid=a,dc=x", "cn", "a")
      end
    end

    it "does not fire when the response arrives within the deadline" do
      socket = FakeSocket.new { |id| bind_success(id) }
      client = LDAP::Client.new(socket, timeout: 5.seconds)

      client.authenticate("cn=admin", "secret").should be(client)
    end

    # Exercises the search path: entries accumulate in @results, then the stream
    # stalls (no SearchResultDone). The timeout must fire and clean up.
    it "times out a search that stalls mid-stream" do
      socket = HangingSocket.new { |id| search_entry(id) }
      client = LDAP::Client.new(socket, timeout: 20.milliseconds)

      expect_raises(LDAP::Client::TimeoutError) do
        client.search(base: "dc=x")
      end
    end
  end
end
