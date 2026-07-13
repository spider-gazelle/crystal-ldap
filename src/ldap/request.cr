require "mutex"
require "../ldap"

class LDAP::Request; end

require "./request/*"

class LDAP::Request
  @msg_id = 0
  @id_mutex = Mutex.new

  # Message IDs run from 1 to Int32::MAX and wrap back to 1.
  # RFC 4511 §4.1.1.1: "The message ID of zero is reserved for unsolicited
  # notifications and MUST NOT be used in any other request."
  def next_message_id
    @id_mutex.synchronize {
      @msg_id = @msg_id >= Int32::MAX ? 1 : @msg_id + 1
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
      BER.new.set_integer(LDAP::PROTOCOL_VERSION),
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

  # RFC 2696 Simple Paged Results control. *cookie* is the opaque cookie from the
  # previous page (empty on the first request); *size* is the requested page size.
  def encode_paged_control(size : Int, cookie : Bytes) : BER
    # controlValue ::= SEQUENCE { size INTEGER, cookie OCTET STRING }
    cookie_ber = BER.new.set_string("", UniversalTags::OctetString)
    cookie_ber.payload = cookie # binary-safe: raw bytes, no String round-trip
    value = LDAP.sequence({
      BER.new.set_integer(size),
      cookie_ber,
    })

    # controlValue must be wrapped as an OCTET STRING (RFC 4511 §4.1.11)
    control_value = BER.new.set_string("", UniversalTags::OctetString)
    control_value.payload = value.to_slice

    LDAP.sequence({
      BER.new.set_string(PAGED_RESULTS, UniversalTags::OctetString),
      BER.new.set_boolean(false),
      control_value,
    })
  end

  # base:   https://tools.ietf.org/html/rfc4511#section-4.5.1.1
  # filter: https://tools.ietf.org/html/rfc4511#section-4.5.1.7
  # scope:  https://tools.ietf.org/html/rfc4511#section-4.5.1.2
  # attrs:      https://tools.ietf.org/html/rfc4511#section-4.5.1.8
  # attrs_only: https://tools.ietf.org/html/rfc4511#section-4.5.1.6
  # deref: https://tools.ietf.org/html/rfc4511#section-4.5.1.3
  # size: https://tools.ietf.org/html/rfc4511#section-4.5.1.4
  # time: https://tools.ietf.org/html/rfc4511#section-4.5.1.5
  def search(
    base : String,
    filter : Filter | String = Filter.equal("objectClass", "*"),
    scope : SearchScope = SearchScope::WholeSubtree,
    attributes : Enumerable(String) | Enumerable(Symbol) = [] of String,
    attributes_only : Bool = false,
    dereference : DereferenceAliases = DereferenceAliases::Always,
    size : Int = 0,
    time : Int = 0,
    sort : String | SortControl | BER | Nil = nil,
    page_size : Int? = nil,
    cookie : Bytes = Bytes.empty,
  )
    attributes = attributes.map { |attr| BER.new.set_string(attr.to_s, UniversalTags::OctetString) }

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

    # Controls (RFC 4511 §4.1.1): controls [0] SEQUENCE OF Control
    controls = [] of BER
    if sort
      controls << (sort.is_a?(BER) ? sort : encode_sort_controls(sort))
    end
    controls << encode_paged_control(page_size, cookie) if page_size

    if controls.empty?
      build(search_request)
    else
      build(search_request, LDAP.context_sequence(controls, 0))
    end
  end

  # https://tools.ietf.org/html/rfc4511#section-4.6
  def modify(dn : String, changes : Enumerable(Modification))
    change_list = changes.map do |change|
      LDAP.sequence({
        BER.new.set_integer(change.operation.value, UniversalTags::Enumerated),
        LDAP.sequence({
          BER.new.set_string(change.type, UniversalTags::OctetString),
          LDAP.set(change.values.map { |value| BER.new.set_string(value, UniversalTags::OctetString) }),
        }),
      })
    end
    build(LDAP.app_sequence({
      BER.new.set_string(dn, UniversalTags::OctetString),
      LDAP.sequence(change_list),
    }, Tag::ModifyRequest))
  end

  # https://tools.ietf.org/html/rfc4511#section-4.7
  def add(dn : String, attributes : Hash(String, Array(String)))
    attribute_list = attributes.map do |type, values|
      LDAP.sequence({
        BER.new.set_string(type, UniversalTags::OctetString),
        LDAP.set(values.map { |value| BER.new.set_string(value, UniversalTags::OctetString) }),
      })
    end
    build(LDAP.app_sequence({
      BER.new.set_string(dn, UniversalTags::OctetString),
      LDAP.sequence(attribute_list),
    }, Tag::AddRequest))
  end

  # https://tools.ietf.org/html/rfc4511#section-4.8
  def delete(dn : String)
    # DelRequest is [APPLICATION 10] LDAPDN — a primitive whose content is the
    # DN itself, not a constructed sequence.
    build(BER.new.set_string(dn, Tag::DeleteRequest.to_i, TagClass::Application))
  end

  # https://tools.ietf.org/html/rfc4511#section-4.9
  def modify_dn(dn : String, new_rdn : String, delete_old_rdn : Bool = true, new_superior : String? = nil)
    fields = [
      BER.new.set_string(dn, UniversalTags::OctetString),
      BER.new.set_string(new_rdn, UniversalTags::OctetString),
      BER.new.set_boolean(delete_old_rdn),
    ]
    # newSuperior is [0] LDAPDN OPTIONAL — a context-specific primitive.
    fields << BER.new.set_string(new_superior, 0, TagClass::ContextSpecific) if new_superior
    build(LDAP.app_sequence(fields, Tag::ModifyRDNRequest))
  end

  # https://tools.ietf.org/html/rfc4511#section-4.10
  def compare(dn : String, attribute : String, value : String)
    ava = LDAP.sequence({
      BER.new.set_string(attribute, UniversalTags::OctetString),
      BER.new.set_string(value, UniversalTags::OctetString),
    })
    build(LDAP.app_sequence({
      BER.new.set_string(dn, UniversalTags::OctetString),
      ava,
    }, Tag::CompareRequest))
  end

  # https://tools.ietf.org/html/rfc4511#section-4.3
  def unbind
    # UnbindRequest is [APPLICATION 2] NULL — a primitive with no content.
    build(BER.new.set_string("", Tag::UnbindRequest.to_i, TagClass::Application))
  end
end
