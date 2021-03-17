require "mutex"
require "openssl"
require "promise"
require "../ldap"

class LDAP::Client
  class TlsError < Error; end

  class AuthError < Error; end

  def initialize(socket, tls_context : OpenSSL::SSL::Context::Client? = nil)
    @results = Hash(Int32, Array(Response)).new do |h, k|
      h[k] = [] of Response
    end

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
    result = write(*@request.authenticate(username, password)).get
    if result.tag.bind_result?
      details = result.parse_bind_response
      result_code = details[:result_code]
      raise AuthError.new("bind failed with #{result_code}: #{details[:error_message]}") unless result_code.success?
    else
      raise Error.new("unexpected response: #{result.tag}")
    end
    self
  rescue e
    raise e
  end

  def search(*args, **opts)
    result = write(*@request.search(*args, **opts)).get
    results = @results.delete(result.id) || [] of Response

    if result.tag.search_result?
      details = result.parse_result
      result_code = details[:result_code]
      raise AuthError.new("search failed with #{result_code}: #{details[:error_message]}") unless result_code.in?(Response::SEARCH_SUCCESS)

      results.map(&.parse_search_data)
    else
      raise Error.new("unexpected response: #{result.tag}")
    end
  end

  protected def parse_response(packet : BER)
    response = Response.from_response packet
    # Search results are returned in multiple packets
    case response.tag
    when Tag::SearchResultReferral
      # TODO::
    when Tag::SearchReturnedData
      @results[response.id] << response
    else
      request = @mutex.synchronize { @requests.delete response.id }
      if request
        request.resolve(response)
      else
        Log.warn { "unexpected message received #{response.inspect}" }
      end
    end
  end

  protected def process!
    socket = @socket
    while !socket.closed?
      data = socket.read_bytes(ASN1::BER)
      parse_response data
    end
  rescue IO::Error
    @mutex.synchronize { close }
  rescue e
    Log.error(exception: e) { e.message }
    @mutex.synchronize do
      @requests.values.each(&.reject(e))
      @requests.clear
      close
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
