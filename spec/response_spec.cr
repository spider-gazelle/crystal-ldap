require "./spec_helper"

# LDAPMessage { messageID, protocolOp } built from the library's own BER
# helpers, so fixtures track the encoder.
private def message(id : Int32, op : LDAP::BER) : LDAP::BER
  LDAP.sequence({LDAP::BER.new.set_integer(id), op})
end

# A result-bearing protocol op: SEQUENCE { resultCode ENUMERATED, matchedDN, errorMessage }.
# `tag` defaults to a known op tag so the Code path can be tested in isolation;
# pass a raw Int to forge an unknown protocol-op tag.
private def result_op(code : Int32, tag = LDAP::Tag::SearchResult) : LDAP::BER
  LDAP.app_sequence({
    LDAP::BER.new.set_integer(code, LDAP::UniversalTags::Enumerated),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
  }, tag)
end

# Wraps a SearchResultDone with a paged-results control carrying *cookie*.
private def done_with_cookie(cookie : Bytes) : LDAP::Response
  op = LDAP.app_sequence({
    LDAP::BER.new.set_integer(0, LDAP::UniversalTags::Enumerated),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
  }, LDAP::Tag::SearchResult)
  control = LDAP::Request.new.encode_paged_control(0, cookie)
  packet = LDAP.sequence({
    LDAP::BER.new.set_integer(1),
    op,
    LDAP.context_sequence([control], 0),
  })
  LDAP::Response.from_response(IO::Memory.new(packet.to_slice).read_bytes(ASN1::BER))
end

describe LDAP::Response do
  describe ".from_response" do
    # A server can send a protocol-op tag we don't model; decoding it must not
    # crash the read fiber with a bare ArgumentError.
    it "preserves an unknown protocol-op tag instead of raising" do
      response = LDAP::Response.from_response(message(1, result_op(0, tag: 30)))
      response.tag.value.should eq(30)
    end
  end

  describe "#parse_result" do
    it "preserves an unknown result code instead of raising" do
      response = LDAP::Response.from_response(message(1, result_op(123)))
      response.parse_result[:result_code].value.should eq(123)
    end

    it "decodes loopDetect (54), completing the RFC 4511 result-code table" do
      response = LDAP::Response.from_response(message(1, result_op(54)))
      response.parse_result[:result_code].should eq(LDAP::Response::Code::LoopDetect)
    end

    it "still decodes a known result code" do
      response = LDAP::Response.from_response(message(1, result_op(49)))
      response.parse_result[:result_code].should eq(LDAP::Response::Code::InvalidCredentials)
    end
  end

  describe "#result_message" do
    it "renders a known code" do
      LDAP::Response.new(LDAP::BER.new.set_integer(1), result_op(0))
        .result_message(LDAP::Response::Code::InvalidCredentials.value)
        .should eq("invalid credentials")
    end

    it "renders an unknown code without raising" do
      response = LDAP::Response.new(LDAP::BER.new.set_integer(1), result_op(0))
      response.result_message(123).should eq("123")
    end
  end

  describe "#paged_cookie" do
    it "returns the cookie from the paged-results control" do
      done_with_cookie(Bytes[0xAB, 0xCD]).paged_cookie.should eq(Bytes[0xAB, 0xCD])
    end

    it "returns empty bytes for an empty cookie (last page)" do
      done_with_cookie(Bytes.empty).paged_cookie.should eq(Bytes.empty)
    end

    it "returns nil when the response has no controls" do
      op = LDAP.app_sequence({
        LDAP::BER.new.set_integer(0, LDAP::UniversalTags::Enumerated),
        LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
        LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
      }, LDAP::Tag::SearchResult)
      packet = LDAP.sequence({LDAP::BER.new.set_integer(1), op})
      resp = LDAP::Response.from_response(IO::Memory.new(packet.to_slice).read_bytes(ASN1::BER))
      resp.paged_cookie.should be_nil
    end
  end
end
