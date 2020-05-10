require "bindata/asn1"
require "log"

module LDAP
  Log = ::Log.for("ldap")

  alias BER = ASN1::BER
  alias TagClass = BER::TagClass
  alias UniversalTags = BER::UniversalTags

  class Error < RuntimeError; end

  VERSION = 3

  enum Tag
    # http://tools.ietf.org/html/rfc4511#section-4.2
    BindRequest = 0
    # http://tools.ietf.org/html/rfc4511#section-4.2.2
    BindResult = 1
    # http://tools.ietf.org/html/rfc4511#section-4.3
    UnbindRequest = 2
    # http://tools.ietf.org/html/rfc4511#section-4.5.1
    SearchRequest = 3
    # http://tools.ietf.org/html/rfc4511#section-4.5.2
    SearchReturnedData = 4
    SearchResult       = 5
    # see also SearchResultReferral (19)
    # http://tools.ietf.org/html/rfc4511#section-4.6
    ModifyRequest  = 6
    ModifyResponse = 7
    # http://tools.ietf.org/html/rfc4511#section-4.7
    AddRequest  = 8
    AddResponse = 9
    # http://tools.ietf.org/html/rfc4511#section-4.8
    DeleteRequest  = 10
    DeleteResponse = 11
    # http://tools.ietf.org/html/rfc4511#section-4.9
    ModifyRDNRequest  = 12
    ModifyRDNResponse = 13
    # http://tools.ietf.org/html/rfc4511#section-4.10
    CompareRequest  = 14
    CompareResponse = 15
    # http://tools.ietf.org/html/rfc4511#section-4.11
    AbandonRequest = 16
    # http://tools.ietf.org/html/rfc4511#section-4.5.2
    SearchResultReferral = 19
    # http://tools.ietf.org/html/rfc4511#section-4.12
    ExtendedRequest  = 23
    ExtendedResponse = 24
    # unused: http://tools.ietf.org/html/rfc4511#section-4.13
    IntermediateResponse = 25
  end

  enum SearchScope
    BaseObject   = 0
    SingleLevel  = 1
    WholeSubtree = 2
  end

  enum DereferenceAliases
    Never  = 0
    Search = 1
    Find   = 2
    Always = 3
  end

  def self.sequence(
    data : Enumerable(ASN1::BER),
    tag_class : TagClass = TagClass::Universal,
    tag : Int | UniversalTags = UniversalTags::Sequence,
    constructed : Bool = true
  ) : ASN1::BER
    sequence = ASN1::BER.new
    sequence.tag_class = tag_class
    sequence.tag_number = tag
    sequence.children = data
    sequence
  end

  def self.set(data : Enumerable(ASN1::BER)) : ASN1::BER
    sequence(
      data,
      TagClass::Universal,
      UniversalTags::Set,
      constructed: true
    )
  end

  def self.app_sequence(data : Enumerable(ASN1::BER), tag) : ASN1::BER
    sequence(
      data,
      TagClass::Application,
      tag.to_i,
      constructed: true
    )
  end

  def self.context_sequence(data : Enumerable(ASN1::BER), tag) : ASN1::BER
    sequence(
      data,
      TagClass::ContextSpecific,
      tag.to_i,
      constructed: true
    )
  end
end

require "./ldap/request"
require "./ldap/response"
require "./ldap/client"
