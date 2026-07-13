require "./spec_helper"

# A reactive multi-response socket: each flushed request is answered with the next
# scripted page (entries + SearchResultDone carrying a paged cookie), echoing the
# request's messageID. Reads block between pages until the next request is flushed.
class PagedSocket < IO
  getter requests = [] of Bytes
  getter? closed = false

  def initialize(&@responder : Int32 -> Bytes)
    @sent = IO::Memory.new
    @incoming = IO::Memory.new
    @ready = Channel(Nil).new(1)
  end

  def read(slice : Bytes) : Int32
    loop do
      n = @incoming.read(slice)
      return n if n > 0
      @ready.receive
      return 0 if @closed
    end
  end

  def write(slice : Bytes) : Nil
    @sent.write(slice)
  end

  def flush
    bytes = @sent.to_slice.dup
    @requests << bytes
    message_id = IO::Memory.new(bytes).read_bytes(ASN1::BER).children[0].get_integer.to_i
    @sent.clear
    @incoming.clear
    @incoming.write @responder.call(message_id)
    @incoming.rewind
    @ready.send(nil)
    self
  end

  def close
    @closed = true
    # Non-blocking wake: signals a parked reader if there is one, no-op otherwise
    # (a full buffer already carries a pending signal). Never blocks.
    select
    when @ready.send(nil)
    else
    end
  end
end

# One page: `dns.size` SearchResultEntry (tag 4) + a SearchResultDone (tag 5) with
# result *code* and a paged-results control carrying *cookie*, all under *id*.
private def page(id : Int32, dns : Array(String), cookie : Bytes, code : Int32 = 0) : Bytes
  io = IO::Memory.new
  dns.each do |entry_dn|
    entry = LDAP.app_sequence({
      LDAP::BER.new.set_string(entry_dn, LDAP::UniversalTags::OctetString),
      LDAP.sequence([] of LDAP::BER),
    }, LDAP::Tag::SearchReturnedData)
    io.write LDAP.sequence({LDAP::BER.new.set_integer(id), entry}).to_slice
  end
  done = LDAP.app_sequence({
    LDAP::BER.new.set_integer(code, LDAP::UniversalTags::Enumerated),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
  }, LDAP::Tag::SearchResult)
  control = LDAP::Request.new.encode_paged_control(0, cookie)
  io.write LDAP.sequence({
    LDAP::BER.new.set_integer(id),
    done,
    LDAP.context_sequence([control], 0),
  }).to_slice
  io.to_slice
end

describe LDAP::Client do
  describe "#search (paged, block form)" do
    it "yields every entry across pages until the cookie is empty" do
      pages = [
        ->(id : Int32) { page(id, ["uid=a", "uid=b"], Bytes[0x01]) },
        ->(id : Int32) { page(id, ["uid=c"], Bytes.empty) },
      ]
      i = 0
      socket = PagedSocket.new { |id| p = pages[i]; i += 1; p.call(id) }
      client = LDAP::Client.new(socket)

      dns = [] of String
      client.search(base: "dc=x", page_size: 2) { |entry| dns << entry.dn }

      dns.should eq(["uid=a", "uid=b", "uid=c"])
      socket.requests.size.should eq(2)
    end

    it "echoes the previous page's cookie in the next request" do
      pages = [
        ->(id : Int32) { page(id, ["uid=a"], Bytes[0xAA, 0xBB]) },
        ->(id : Int32) { page(id, ["uid=b"], Bytes.empty) },
      ]
      i = 0
      socket = PagedSocket.new { |id| p = pages[i]; i += 1; p.call(id) }
      client = LDAP::Client.new(socket)
      client.search(base: "dc=x", page_size: 1) { |_| }

      # 2nd request's paged control must carry the cookie from page 1
      msg = IO::Memory.new(socket.requests[1]).read_bytes(ASN1::BER)
      control = msg.children[2].children[0]
      inner = IO::Memory.new(control.children[2].get_string.to_slice).read_bytes(ASN1::BER)
      inner.children[1].get_string.to_slice.should eq(Bytes[0xAA, 0xBB])
    end

    it "raises SearchLimitError (empty entries) when a page hits a size limit" do
      # code 4 = sizeLimitExceeded, empty cookie ends the loop
      socket = PagedSocket.new { |id| page(id, ["uid=a"], Bytes.empty, code: 4) }
      client = LDAP::Client.new(socket)

      yielded = [] of String
      ex = expect_raises(LDAP::Client::SearchLimitError) do
        client.search(base: "dc=x", page_size: 10) { |e| yielded << e.dn }
      end
      yielded.should eq(["uid=a"]) # entry was streamed before the raise
      ex.entries.empty?.should be_true
    end

    it "raises OperationError on a non-success, non-limit page code" do
      # code 1 = operationsError
      socket = PagedSocket.new { |id| page(id, [] of String, Bytes.empty, code: 1) }
      client = LDAP::Client.new(socket)

      expect_raises(LDAP::Client::OperationError) do
        client.search(base: "dc=x", page_size: 10) { |_| }
      end
    end
  end
end
