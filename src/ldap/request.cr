require "mutex"
require "../ldap"

class LDAP::Request; end

require "./request/*"

class LDAP::Request
  @msg_id = -1
  @id_mutex = Mutex.new

  def next_message_id
    @id_mutex.synchronize {
      begin
        @msg_id = @msg_id + 1
      rescue OverflowError
        @msg_id = 0
      end
    }
  end

  def build(request : BER, controls : BER? = nil, message_id = next_message_id)
    # construct message id
    id_ber = BER.new.set_integer(message_id)
    sequence = controls ? {id_ber, request, controls} : {id_ber, request}
    {message_id, LDAP.sequence(sequence)}
  end

  START_TLS_OID = "1.3.6.1.4.1.1466.20037"

  def start_tls
    build(LDAP.app_sequence({
      BER.new.set_string(START_TLS_OID, 0, TagClass::ContextSpecific),
    }, Tag::ExtendedRequest))
  end

  def authenticate(username : String = "", password : String = "")
    build(LDAP.app_sequence({
      BER.new.set_integer(3),
      BER.new.set_string(username, UniversalTags::OctetString),
      BER.new.set_string(password, 0, TagClass::ContextSpecific),
    }, Tag::BindRequest))
  end

  alias SortControl = NamedTuple(name: String, rule: String, reverse: Bool) | NamedTuple(name: String, reverse: Bool)

  PAGED_RESULTS = "1.2.840.113556.1.4.319" # Microsoft evil from RFC 2696
  DELETE_TREE   = "1.2.840.113556.1.4.805"
  SORT_REQUEST  = "1.2.840.113556.1.4.473"
  SORT_RESPONSE = "1.2.840.113556.1.4.474"

  def encode_sort_controls(*sort_controls : String | SortControl)
    sort_controls = sort_controls.map do |control|
      if control.is_a?(SortControl)
        LDAP.sequence({
          BER.new.set_string(control[:name], UniversalTags::OctetString),
          BER.new.set_string(control[:rule]? || "", UniversalTags::OctetString),
          BER.new.set_boolean(control[:reverse]),
        })
      else
        LDAP.sequence({
          BER.new.set_string(control, UniversalTags::OctetString),
          BER.new.set_string("", UniversalTags::OctetString),
          BER.new.set_boolean(false),
        })
      end
    end

    # Control sequence needs to be encoded as an OctetString
    # https://tools.ietf.org/html/rfc2891
    controls = BER.new.set_string("", UniversalTags::OctetString)
    controls.payload = LDAP.sequence(sort_controls).to_slice

    # convert to actual message
    LDAP.sequence({
      BER.new.set_string(SORT_REQUEST, UniversalTags::OctetString),
      BER.new.set_boolean(false),
      controls,
    })
  end

  # base:   https://tools.ietf.org/html/rfc4511#section-4.5.1.1
  # filter: https://tools.ietf.org/html/rfc4511#section-4.5.1.7
  # scope:  https://tools.ietf.org/html/rfc4511#section-4.5.1.2
  # attrs:      https://tools.ietf.org/html/rfc4511#section-4.5.1.8
  # attrs_only: https://tools.ietf.org/html/rfc4511#section-4.5.1.6
  # referrals:  https://tools.ietf.org/html/rfc4511#section-4.5.3
  # deref: https://tools.ietf.org/html/rfc4511#section-4.5.1.3
  # size: https://tools.ietf.org/html/rfc4511#section-4.5.1.4
  # time: https://tools.ietf.org/html/rfc4511#section-4.5.1.5
  def search(
    base : String,
    filter : Filter | String = Filter.equal("objectClass", "*"),
    scope : SearchScope = SearchScope::WholeSubtree,
    attributes : Enumerable(String) | Enumerable(Symbol) = [] of String,
    attributes_only : Bool = false,
    return_referrals : Bool = true,
    dereference : DereferenceAliases = DereferenceAliases::Always,
    size : Int = 0,
    time : Int = 0,
    paged_searches_supported : Bool = false,
    sort : String | SortControl | BER | Nil = nil
  )
    attributes = attributes.map { |a| BER.new.set_string(a.to_s, UniversalTags::OctetString) }

    # support string based filters
    filter = FilterParser.parse(filter) if filter.is_a?(String)

    # Build search request
    search_request = LDAP.app_sequence({
      BER.new.set_string(base, UniversalTags::OctetString),
      BER.new.set_integer(scope.to_u8, UniversalTags::Enumerated),
      BER.new.set_integer(dereference.to_u8, UniversalTags::Enumerated),
      BER.new.set_integer(size),
      BER.new.set_integer(time),
      BER.new.set_boolean(attributes_only),
      filter.to_ber,
      LDAP.sequence(attributes),
    }, Tag::SearchRequest)

    # Sort controls
    if sort
      sort_control = case sort
                     when String | SortControl
                       encode_sort_controls(sort)
                     when BER
                       sort
                     end

      build(search_request, sort_control)
    else
      build(search_request)
    end
  end
end
