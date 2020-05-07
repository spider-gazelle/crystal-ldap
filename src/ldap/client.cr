require "mutex"
require "openssl"
require "promise"
require "../ldap"

class LDAP::Client
  class TlsError < Exception; end

  def initialize(socket, tls_context : OpenSSL::SSL::Context::Client? = nil)
    # Send without delay as we will be using `#flush`
    socket.tcp_nodelay = true if socket.responds_to?(:tcp_nodelay=)

    # Attempt to start TLS if required
    wrapped_socket = tls_context ? start_tls(socket, tls_context) : socket

    # Ensure the underlying socket expects to be manually flushed
    socket.sync = false if socket.responds_to?(:sync=)
    @socket = wrapped_socket.as(IO)

    # Start processing responses
    spawn { process! }
  end

  @mutex = Mutex.new
  @socket : IO
  @request = Request.new
  @requests = {} of Int32 => Promise::DeferredPromise(Response)

  def closed?
    @socket.closed?
  end

  def close
    @socket.close unless closed?
  end

  def write(message_id : Int32, sequence : BER)
    @mutex.synchronize do
      raise LDAP::Error.new("connection closed") if @socket.closed?

      @socket.write_bytes sequence
      @socket.flush
      @requests[message_id] = Promise.new(Response)
    end
  end

  def authenticate(username : String = "", password : String = "")
    write(*@request.authenticate(username, password))
  end

  def parse_response(packet : BER)
    response = Response.from_response packet
    request = @mutex.synchronize { @requests.delete response.id }
    if request
      request.resolve(response)
    else
      Log.warn { "unexpected message received #{response.inspect}" }
    end
  end

  protected def process!
    socket = @socket
    while !socket.closed?
      data = socket.read_bytes(ASN1::BER)
      parse_response data
    end
    # Clean up pending responses


  rescue IO::Error
    @mutex.synchronize { @socket.close }
  rescue e
    Log.error(exception: e) { e.message }
    @mutex.synchronize do
      @requests.values.each(&.reject(e))
      @requests.clear
      @socket.close
    end
  ensure
    @mutex.synchronize do
      values = @requests.values
      if !values.empty?
        err = TlsError.new("socket closed")
        values.each(&.reject(err))
        @requests.clear
      end
    end
  end

  protected def start_tls(socket, context)
    # We want to sync here so the lib can negotiate TLS
    socket.sync = true if socket.responds_to?(:sync=)
    socket.write @request.start_tls[1].to_slice

    # Check if the remote supports TLS
    response = Response.from_response socket.read_bytes(ASN1::BER)
    raise TlsError.new("expected a start_tls result") unless response.tag.extended_response?
    result = response.parse_result[:result_code]
    raise TlsError.new("start_tls failed with: #{result}") unless result.success?

    OpenSSL::SSL::Socket::Client.new(socket, context: context, sync_close: true)
  end
end
