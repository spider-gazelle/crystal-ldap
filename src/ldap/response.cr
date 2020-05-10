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
    NamingViolation              = 64
    ObjectClassViolation         = 65
    NotAllowedOnNonLeaf          = 66
    NotAllowedOnRDN              = 67
    EntryAlreadyExists           = 68
    ObjectClassModsProhibited    = 69
    AffectsMultipleDSAs          = 71
    Other                        = 80
  end

  SUCCESS_CODES  = {Code::Success, Code::CompareFalse, Code::CompareTrue, Code::Referral, Code::SaslBindInProgress}
  SEARCH_SUCCESS = {Code::Success, Code::TimeLimitExceeded, Code::SizeLimitExceeded}

  def initialize(message_id, payload, @control = nil)
    @id = message_id.get_integer.to_i
    @tag = LDAP::Tag.from_value(payload.tag_number)
    @payload = payload.children
  end

  getter id : Int32
  getter tag : ::LDAP::Tag
  getter payload : Array(BER)
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

  # A Bind Response may have an additional field, ID [7], serverSaslCreds,
  # per RFC 2251 pgh 4.2.3.
  def parse_bind_response
    sequence = @payload
    raise LDAP::Error.new("Invalid LDAP Bind Response size") unless sequence.size >= 3

    result = parse_result
    result = result.merge({server_sasl_creds: sequence[3]}) if sequence.size >= 4
    result
  end

  def parse_result
    sequence = @payload
    raise LDAP::Error.new("Invalid LDAP result size") unless sequence.size >= 3

    {
      result_code:   Code.from_value(sequence[0].get_integer),
      matched_dn:    sequence[1].get_string,
      error_message: sequence[2].get_string,
    }
  end

  def parse_search_data
    entry = @payload
    raise Error.new("Invalid entry size in search results") unless entry.size >= 2
    search_entry = entry[0].get_string
    data = {
      "dn" => [search_entry],
    }
    entry[1].children.each do |attribute|
      key_value = attribute.children
      raise Error.new("Invalid attribute size in search results") unless key_value.size >= 2
      data[key_value[0].get_string] = key_value[1].children.map(&.get_string)
    end
    data
  end

  def result_message(code : Int)
    Code.from_value(code).to_s.underscore.gsub('_', ' ')
  rescue e
    "unknown result (#{code})"
  end
end
