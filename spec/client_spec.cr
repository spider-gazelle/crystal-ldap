require "./helper"

# A minimal in-memory duplex IO standing in for a TCP socket, so the client's
# read fiber + request/response correlation can be exercised without a server.
#
# It is *reactive* like a real server: the scripted response is produced only
# after the client has sent (flushed) its request, and is built from the actual
# messageID the client emitted — so these specs don't care whether IDs start at
# 0 or 1, and the read fiber can't race ahead of #write under -Dpreview_mt.
class FakeSocket < IO
  getter sent = IO::Memory.new
  getter? closed = false

  def initialize(&@responder : Int32 -> Bytes)
    @incoming = IO::Memory.new
    @request_sent = Channel(Nil).new(1)
    @reads_opened = false
  end

  def read(slice : Bytes) : Int32
    unless @reads_opened
      @reads_opened = true
      @request_sent.receive
    end
    @incoming.read(slice)
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
  end
end

private def concat(*parts : Bytes) : Bytes
  io = IO::Memory.new
  parts.each { |part| io.write part }
  io.to_slice
end

# LDAPMessage byte streams built with the library's own BER primitives, so the
# fixtures stay in sync with the encoder.
private def search_entry(id : Int32, dn : String, attrs : Hash(String, Array(String) | Array(Bytes)))
  attr_seq = attrs.map do |key, values|
    value_bers = values.map { |v| LDAP::BER.new.set_string(v.is_a?(Bytes) ? String.new(v) : v, LDAP::UniversalTags::OctetString) }
    LDAP.sequence({
      LDAP::BER.new.set_string(key, LDAP::UniversalTags::OctetString),
      LDAP.set(value_bers),
    })
  end
  op = LDAP.app_sequence({
    LDAP::BER.new.set_string(dn, LDAP::UniversalTags::OctetString),
    LDAP.sequence(attr_seq),
  }, LDAP::Tag::SearchReturnedData)
  LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
end

private def search_done(id : Int32, code : Int32 = 0)
  op = LDAP.app_sequence({
    LDAP::BER.new.set_integer(code, LDAP::UniversalTags::Enumerated),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
  }, LDAP::Tag::SearchResult)
  LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
end

describe LDAP::Client do
  describe "#search" do
    it "accumulates multiple SearchResultEntry packets into one result set" do
      socket = FakeSocket.new do |id|
        concat(
          search_entry(id, "uid=a,dc=example,dc=com", {"cn" => ["Alice"], "objectClass" => ["person", "top"]}),
          search_entry(id, "uid=b,dc=example,dc=com", {"cn" => ["Bob"]}),
          search_done(id),
        )
      end
      client = LDAP::Client.new(socket)
      results = client.search(base: "dc=example,dc=com", filter: "(objectClass=*)")

      results.size.should eq(2)
      results[0]["dn"].should eq(["uid=a,dc=example,dc=com"])
      results[0]["cn"].should eq(["Alice"])
      results[0]["objectClass"].should eq(["person", "top"])
      results[1]["dn"].should eq(["uid=b,dc=example,dc=com"])
      results[1]["cn"].should eq(["Bob"])
    end

    it "returns an empty array when the search yields no entries" do
      socket = FakeSocket.new { |id| search_done(id) }
      client = LDAP::Client.new(socket)
      client.search(base: "dc=example,dc=com", filter: "(cn=nobody)").should eq([] of Hash(String, Array(String)))
    end

    # End-to-end consequence of tolerant tag decoding: a response carrying an
    # unmodelled protocol-op tag must not crash the read fiber — it resolves the
    # request and surfaces as a clean per-call error to the caller.
    it "surfaces an unexpected response tag as a clean error, not a read-fiber crash" do
      unknown_tag = 30
      socket = FakeSocket.new do |id|
        op = LDAP.app_sequence({
          LDAP::BER.new.set_integer(0, LDAP::UniversalTags::Enumerated),
          LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
          LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
        }, unknown_tag)
        LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
      end
      client = LDAP::Client.new(socket)

      expect_raises(LDAP::Error, /unexpected response/) do
        client.search(base: "dc=example,dc=com")
      end
    end

    # Documents current behavior: octet-string attribute values are carried
    # verbatim. Binary values (objectGUID, userCertificate, ...) survive in the
    # String and are recoverable via String#to_slice. (Typed Bytes accessors
    # are a separate API concern.)
    it "preserves the raw bytes of binary attribute values" do
      guid = Bytes[0x00, 0xff, 0xfe, 0x80, 0x41, 0x00, 0xc3, 0x28]
      socket = FakeSocket.new do |id|
        concat(search_entry(id, "uid=a,dc=example,dc=com", {"objectGUID" => [guid]}), search_done(id))
      end
      client = LDAP::Client.new(socket)
      results = client.search(base: "dc=example,dc=com")

      results[0]["objectGUID"][0].to_slice.should eq(guid)
    end
  end

  describe "max_message_size" do
    # A hostile/buggy server can declare a huge length and force the read fiber
    # to allocate (or read) far beyond any real message. The per-client cap makes
    # bindata reject the frame before allocating; here a 1 KiB cap rejects a frame
    # declaring 5000 bytes of content. (5000, not ~2 GiB, so the test is safe to
    # run even against an unbounded read.)
    it "rejects a message whose declared length exceeds the cap" do
      # SEQUENCE, long-form length 0x1388 (5000), no payload follows.
      socket = FakeSocket.new { |_id| Bytes[0x30, 0x82, 0x13, 0x88] }
      client = LDAP::Client.new(socket, max_message_size: 1024)

      expect_raises(ASN1::ContentTooLarge) do
        client.search(base: "dc=example,dc=com")
      end
    end

    # The dangerous case the cap must also stop: a small outer frame that smuggles
    # a child declaring an oversized length. bindata propagates the cap into
    # children, so it's rejected at the cap check — before any large allocation —
    # while decoding the message.
    it "rejects an oversized child smuggled inside a small frame" do
      # SEQUENCE (len 6) { OCTET STRING declaring ~2 GiB }: outer fits the cap, child doesn't.
      socket = FakeSocket.new { |_id| Bytes[0x30, 0x06, 0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF] }
      client = LDAP::Client.new(socket, max_message_size: 1024)

      expect_raises(ASN1::ContentTooLarge) do
        client.search(base: "dc=example,dc=com")
      end
    end
  end
end
