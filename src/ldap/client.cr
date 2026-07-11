require "mutex"
require "openssl"
require "promise"
require "../ldap"

class LDAP::Client
  class TlsError < Error; end

  # Raised when a received message exceeds `max_message_size` (see `#initialize`).
  class MessageTooLargeError < Error; end

  # Raised when an operation returns a non-success LDAP result code.
  class OperationError < Error
    getter result_code : Response::Code
    getter matched_dn : String
    getter error_message : String

    def initialize(operation : String, @result_code : Response::Code, @matched_dn : String, @error_message : String)
      super("#{operation} failed with #{@result_code}: #{@error_message}")
    end
  end

  # Bind failure is an authentication concern callers often handle on its own.
  class AuthError < OperationError; end

  # *max_message_size* caps how many bytes the BER decoder will allocate or read
  # for a single received message and its nested values, guarding against a
  # hostile server forcing a huge allocation. Defaults to 16 MiB; `0` or a
  # negative value disables the bound.
  def initialize(socket, tls_context : OpenSSL::SSL::Context::Client? = nil, @max_message_size : Int32 = 16 * 1024 * 1024)
    @results = Hash(Int32, Array(Response)).new do |hash, key|
      hash[key] = [] of Response
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
      raise AuthError.new("bind", result_code, details[:matched_dn], details[:error_message]) unless result_code.success?
    else
      raise Error.new("unexpected response: #{result.tag}")
    end
    self
  rescue e
    close
    raise e
  end

  def search(*args, **opts)
    result = write(*@request.search(*args, **opts)).get
    results = @mutex.synchronize { @results.delete(result.id) } || [] of Response

    if result.tag.search_result?
      details = result.parse_result
      result_code = details[:result_code]
      raise OperationError.new("search", result_code, details[:matched_dn], details[:error_message]) unless result_code.in?(Response::SEARCH_SUCCESS)

      # parse_search_data decodes nested children here (caller fiber); a cap
      # breach must surface typed like the read-fiber paths.
      wrap_too_large { results.map(&.parse_search_data) }
    else
      raise Error.new("unexpected response: #{result.tag}")
    end
  end

  # https://tools.ietf.org/html/rfc4511#section-4.6
  def modify(dn : String, changes : Enumerable(Modification)) : self
    expect_result(@request.modify(dn, changes), Tag::ModifyResponse, "modify")
    self
  end

  # https://tools.ietf.org/html/rfc4511#section-4.7
  def add(dn : String, attributes : Hash(String, Array(String))) : self
    expect_result(@request.add(dn, attributes), Tag::AddResponse, "add")
    self
  end

  # https://tools.ietf.org/html/rfc4511#section-4.8
  def delete(dn : String) : self
    expect_result(@request.delete(dn), Tag::DeleteResponse, "delete")
    self
  end

  # https://tools.ietf.org/html/rfc4511#section-4.9
  def modify_dn(dn : String, new_rdn : String, delete_old_rdn : Bool = true, new_superior : String? = nil) : self
    expect_result(@request.modify_dn(dn, new_rdn, delete_old_rdn, new_superior), Tag::ModifyRDNResponse, "modify_dn")
    self
  end

  # https://tools.ietf.org/html/rfc4511#section-4.10
  # Returns whether the entry's attribute holds the asserted value.
  def compare(dn : String, attribute : String, value : String) : Bool
    result = write(*@request.compare(dn, attribute, value)).get
    raise Error.new("unexpected response: #{result.tag}") unless result.tag.compare_response?
    details = result.parse_result
    result_code = details[:result_code]
    case result_code
    when .compare_true?  then true
    when .compare_false? then false
    else
      raise OperationError.new("compare", result_code, details[:matched_dn], details[:error_message])
    end
  end

  # https://tools.ietf.org/html/rfc4511#section-4.3
  # Sends an UnbindRequest (which has no response) and closes the connection.
  def unbind : Nil
    _, request = @request.unbind
    @mutex.synchronize do
      # Idempotent teardown: unlike #write, a closed socket is a no-op, not an error.
      unless @socket.closed?
        @socket.write_bytes request
        @socket.flush
      end
    end
    close
  end

  # Sends a single-result operation, awaits its response, and raises
  # OperationError on a non-success result code.
  private def expect_result(request : {Int32, BER}, expected : Tag, operation : String) : Response
    result = write(*request).get
    raise Error.new("unexpected response: #{result.tag}") unless result.tag == expected
    details = result.parse_result
    unless details[:result_code].success?
      raise OperationError.new(operation, details[:result_code], details[:matched_dn], details[:error_message])
    end
    result
  end

  protected def parse_response(packet : BER)
    response = Response.from_response packet
    # Search results are returned in multiple packets
    case response.tag
    when Tag::SearchResultReferral
      # TODO::
    when Tag::SearchReturnedData
      # Guarded by the same mutex as @requests: the read fiber appends here
      # while a caller fiber deletes in #search — without this they race the
      # Hash under multi-threading (-Dpreview_mt).
      @mutex.synchronize { @results[response.id] << response }
    else
      request = @mutex.synchronize { @requests.delete response.id }
      if request
        request.resolve(response)
      else
        Log.warn { "unexpected message received #{response.inspect}" }
      end
    end
  end

  # Read one LDAPMessage, capping how much the BER decoder will allocate/read so
  # a hostile or buggy server can't force a huge allocation (see the
  # *max_message_size* constructor option).
  private def read_message(io : IO) : BER
    wrap_too_large do
      message = BER.new
      message.max_content_length = @max_message_size
      message.read(io)
      message
    end
  end

  # Re-raises bindata's `ASN1::ContentTooLarge` (from the `max_message_size` cap)
  # as an LDAP-typed error, so callers only ever see `LDAP::Error` subclasses.
  private def wrap_too_large(&)
    yield
  rescue ex : ASN1::ContentTooLarge
    raise MessageTooLargeError.new(ex.message)
  end

  protected def process!
    socket = @socket
    while !socket.closed?
      data = read_message(socket)
      parse_response data
    end
  rescue IO::Error
    @mutex.synchronize { close }
  rescue e
    # A ContentTooLarge raised while decoding nested children surfaces here as an
    # LDAP-typed error (the read_message rescue only covers the top-level frame).
    error = e.is_a?(ASN1::ContentTooLarge) ? MessageTooLargeError.new(e.message) : e
    # A deliberate local #close (e.g. after a failed bind) unblocks the parked
    # read_bytes and surfaces as a decode error here — that is an expected
    # teardown, not a fault to log. Logging it raced the Log dispatcher at
    # shutdown and crashed with Channel::ClosedError (issue #2).
    Log.error(exception: error) { error.message } unless @socket.closed?
    @mutex.synchronize do
      @requests.values.each(&.reject(error))
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
    response = Response.from_response read_message(socket)
    raise TlsError.new("expected a start_tls result") unless response.tag.extended_response?
    result = response.parse_result[:result_code]
    raise TlsError.new("start_tls failed with: #{result}") unless result.success?

    OpenSSL::SSL::Socket::Client.new(socket, context: context, sync_close: true)
  end
end
