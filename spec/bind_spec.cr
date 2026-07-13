require "./spec_helper"

describe LDAP do
  user = "cn=read-only-admin,dc=example,dc=com"
  pass = "password"
  bind_request = Bytes[0x30, 0x38, 0x02, 0x01, 0x01, 0x60, 0x33, 0x02, 0x01, 0x03, 0x04, 0x24, 0x63, 0x6e, 0x3d, 0x72,
    0x65, 0x61, 0x64, 0x2d, 0x6f, 0x6e, 0x6c, 0x79, 0x2d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2c, 0x64,
    0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d,
    0x80, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
  ]
  bind_success = Bytes[0x30, 0x0c, 0x02, 0x01, 0x00, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]

  it "should generate a start TLS request" do
    raw_req = Bytes[0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31,
      0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34, 0x36, 0x36, 0x2e, 0x32, 0x30, 0x30, 0x33, 0x37,
    ]

    req = LDAP::Request.new
    _, packet = req.start_tls
    packet.to_slice.should eq(raw_req)
  end

  it "should parse a start TLS response" do
    raw_resp = Bytes[0x30, 0x0c, 0x02, 0x01, 0x00, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]
    io = IO::Memory.new(raw_resp)
    ber = io.read_bytes(ASN1::BER)

    response = LDAP::Response.from_response(ber)
    response.id.should eq(0)
    response.tag.should eq(LDAP::Tag::ExtendedResponse)

    response.parse_result.should eq({
      result_code:   LDAP::Response::Code::Success,
      matched_dn:    "",
      error_message: "",
    })
  end

  it "should generate a bind request" do
    req = LDAP::Request.new
    _, packet = req.authenticate(user, pass)
    packet.to_slice.should eq(bind_request)
  end

  it "encodes the LDAP protocol version from PROTOCOL_VERSION" do
    LDAP::PROTOCOL_VERSION.should eq(3)

    _, packet = LDAP::Request.new.authenticate(user, pass)
    bind_op = IO::Memory.new(packet.to_slice).read_bytes(ASN1::BER).children[1]
    bind_op.children[0].get_integer.should eq(LDAP::PROTOCOL_VERSION)
  end

  it "should parse a bind success response" do
    io = IO::Memory.new(bind_success)
    ber = io.read_bytes(ASN1::BER)

    response = LDAP::Response.from_response(ber)
    response.id.should eq(0)
    response.tag.should eq(LDAP::Tag::BindResult)

    response.parse_bind_response.should eq({
      result_code:       LDAP::Response::Code::Success,
      matched_dn:        "",
      error_message:     "",
      server_sasl_creds: nil,
    })
  end

  # BindResponse ::= LDAPResult + referral [3] OPTIONAL + serverSaslCreds [7]
  # OPTIONAL — the 4th element is NOT always the credentials; dispatch by tag.
  it "reads serverSaslCreds from its [7] tag, not by position" do
    op = LDAP.app_sequence({
      LDAP::BER.new.set_integer(14, LDAP::UniversalTags::Enumerated), # saslBindInProgress
      LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
      LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
      LDAP::BER.new.set_string("creds", 7, LDAP::TagClass::ContextSpecific),
    }, LDAP::Tag::BindResult)
    packet = LDAP.sequence({LDAP::BER.new.set_integer(1), op})
    response = LDAP::Response.from_response(IO::Memory.new(packet.to_slice).read_bytes(ASN1::BER))

    creds = response.parse_bind_response[:server_sasl_creds]
    creds.should_not be_nil
    String.new(creds.get_bytes).should eq("creds") if creds
  end

  it "does not mistake a bind referral [3] for serverSaslCreds" do
    op = LDAP.app_sequence({
      LDAP::BER.new.set_integer(10, LDAP::UniversalTags::Enumerated), # referral
      LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
      LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
      LDAP.context_sequence({LDAP::BER.new.set_string("ldap://b/", LDAP::UniversalTags::OctetString)}, 3),
    }, LDAP::Tag::BindResult)
    packet = LDAP.sequence({LDAP::BER.new.set_integer(1), op})
    response = LDAP::Response.from_response(IO::Memory.new(packet.to_slice).read_bytes(ASN1::BER))

    response.parse_bind_response[:server_sasl_creds].should be_nil
  end
end
