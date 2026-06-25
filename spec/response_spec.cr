require "./helper"

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
end
