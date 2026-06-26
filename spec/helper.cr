require "spec"
require "../src/ldap"

# A minimal in-memory duplex IO standing in for a TCP socket, so the client's
# read fiber + request/response correlation can be exercised without a server.
#
# It is *reactive* like a real server: the scripted response is produced only
# after the client has sent (flushed) its request, and is built from the actual
# messageID the client emitted — so specs don't care whether IDs start at 0 or 1,
# and the read fiber can't race ahead of #write under -Dpreview_mt.
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
