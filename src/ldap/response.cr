require "../ldap"

class LDAP::Response
  enum Code
    # https://tools.ietf.org/html/rfc4511#section-4.1.9
    # https://tools.ietf.org/html/rfc4511#appendix-A
    Success                      =  0
    OperationsError              =  1
    ProtocolError                =  2
    TimeLimitExceeded            =  3
    SizeLimitExceeded            =  4
    CompareFalse                 =  5
    CompareTrue                  =  6
    AuthMethodNotSupported       =  7
    StrongerAuthRequired         =  8
    Referral                     = 10
    AdminLimitExceeded           = 11
    UnavailableCriticalExtension = 12
    ConfidentialityRequired      = 13
    SaslBindInProgress           = 14
    NoSuchAttribute              = 16
    UndefinedAttributeType       = 17
    InappropriateMatching        = 18
    ConstraintViolation          = 19
    AttributeOrValueExists       = 20
    InvalidAttributeSyntax       = 21
    NoSuchObject                 = 32
    AliasProblem                 = 33
    InvalidDNSyntax              = 34
    AliasDereferencingProblem    = 36
    InappropriateAuthentication  = 48
    InvalidCredentials           = 49
    InsufficientAccessRights     = 50
    Busy                         = 51
    Unavailable                  = 52
    UnwillingToPerform           = 53
    LoopDetect                   = 54
    NamingViolation              = 64
    ObjectClassViolation         = 65
    NotAllowedOnNonLeaf          = 66
    NotAllowedOnRDN              = 67
    EntryAlreadyExists           = 68
    ObjectClassModsProhibited    = 69
    AffectsMultipleDSAs          = 71
    Other                        = 80
  end

  def initialize(message_id, payload, @control = nil)
    @id = message_id.get_integer.to_i
    # Tag.new (not from_value) so an unmodelled protocol-op tag is preserved
    # rather than crashing the read fiber with a bare ArgumentError.
    @tag = LDAP::Tag.new(payload.tag_number.to_i32)
    @payload = payload.children
  end

  getter id : Int32
  getter tag : ::LDAP::Tag
  # The raw protocol-op children — bindata's BER stays off the public surface;
  # consumers use the typed accessors (parse_result, parse_entry, referral, …).
  private getter payload : Array(BER)
  getter control : BER?

  def self.from_response(packet : BER) : Response
    raise LDAP::Error.new("invalid LDAP packet, expected sequence") unless packet.sequence?

    children = packet.children
    size = children.size
    case size
    when 3
      Response.new(children[0], children[1], children[2])
    when 2
      Response.new(children[0], children[1])
    else
      raise LDAP::Error.new("invalid LDAP packet, bad sequence size #{size}")
    end
  end

  # A BindResponse is an LDAPResult plus two OPTIONAL trailing fields —
  # referral [3] and serverSaslCreds [7] (RFC 4511 §4.2.2) — so the 4th element
  # is not always the credentials: dispatch by context tag, never by position.
  def parse_bind_response
    sequence = @payload
    raise LDAP::Error.new("Invalid LDAP Bind Response size") unless sequence.size >= 3

    creds = sequence[3..]?.try &.find { |field| field.tag_number.to_i == 7 }
    parse_result.merge({server_sasl_creds: creds})
  end

  def parse_result
    sequence = @payload
    raise LDAP::Error.new("Invalid LDAP result size") unless sequence.size >= 3

    {
      result_code:   Code.new(sequence[0].get_integer.to_i32!),
      matched_dn:    sequence[1].get_string,
      error_message: sequence[2].get_string,
    }
  end

  # The RFC 2696 paged-results cookie carried on a SearchResultDone, or nil if the
  # response has no such control. An empty cookie signals the final page.
  def paged_cookie : Bytes?
    controls = @control
    return nil if controls.nil?
    controls.children.each do |control|
      fields = control.children
      next if fields.empty?
      next unless fields[0].get_string == Request::PAGED_RESULTS
      # controlValue (last field): OCTET STRING wrapping SEQUENCE { size, cookie }
      inner = IO::Memory.new(fields[-1].get_string.to_slice).read_bytes(ASN1::BER)
      return inner.children[1].get_string.to_slice
    end
    nil
  end

  # The referral [3] URIs of an LDAPResult (present when resultCode is referral),
  # or nil when the field is absent. Only meaningful on a search/modify/compare
  # result — for those, the optional 4th payload element is the referral field
  # (a bind response's optional 4th element is serverSaslCreds, read separately).
  def referral : Array(String)?
    field = @payload[3]?
    return nil if field.nil?
    field.children.map(&.get_string)
  end

  # The URIs carried by a SearchResultReference (tag 19), whose payload is the
  # SEQUENCE OF URI directly.
  def referral_uris : Array(String)
    @payload.map(&.get_string)
  end

  def parse_entry : LDAP::Entry
    entry = @payload
    raise Error.new("Invalid entry size in search results") unless entry.size >= 2
    dn = entry[0].get_string
    attributes = Hash(String, Array(Bytes)).new
    entry[1].children.each do |attribute|
      key_value = attribute.children
      raise Error.new("Invalid attribute size in search results") unless key_value.size >= 2
      # Values are raw bytes: octet strings are not guaranteed to be UTF-8.
      attributes[key_value[0].get_string] = key_value[1].children.map(&.get_bytes)
    end
    LDAP::Entry.new(dn, attributes)
  end

  def result_message(code : Int)
    Code.new(code.to_i32!).to_s.underscore.gsub('_', ' ')
  end
end
