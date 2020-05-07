require "./helper"

describe LDAP do
  user = "cn=read-only-admin,dc=example,dc=com"
  pass = "password"
  bind_request = Bytes[0x30, 0x38, 0x02, 0x01, 0x00, 0x60, 0x33, 0x02, 0x01, 0x03, 0x04, 0x24, 0x63, 0x6e, 0x3d, 0x72,
    0x65, 0x61, 0x64, 0x2d, 0x6f, 0x6e, 0x6c, 0x79, 0x2d, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2c, 0x64,
    0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d,
    0x80, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
  ]
  bind_success = Bytes[0x30, 0x0c, 0x02, 0x01, 0x00, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]

  it "should generate a start TLS request" do
    raw_req = Bytes[0x30, 0x1d, 0x02, 0x01, 0x00, 0x77, 0x18, 0x80, 0x16, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31,
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

  it "should parse a bind success response" do
    io = IO::Memory.new(bind_success)
    ber = io.read_bytes(ASN1::BER)

    response = LDAP::Response.from_response(ber)
    response.id.should eq(0)
    response.tag.should eq(LDAP::Tag::BindResult)

    response.parse_bind_response.should eq({
      result_code:   LDAP::Response::Code::Success,
      matched_dn:    "",
      error_message: "",
    })
  end

  it "should use the client to bind to a host" do
    # emulate a network connection
    local = IO::Stapled.new(*IO.pipe, true)
    remote = IO::Stapled.new(*IO.pipe, true)

    socket = IO::Stapled.new(remote, local, true)
    server = IO::Stapled.new(local, remote, true)

    client = LDAP::Client.new(socket)
    auth_promise = client.authenticate(user, pass)

    # check the client sent the bind request
    request = server.read_bytes(ASN1::BER)
    request.to_slice.should eq(bind_request)
    server.write(bind_success)

    # check he client received the response
    response = auth_promise.get
    response.id.should eq(0)
    response.tag.should eq(LDAP::Tag::BindResult)

    response.parse_bind_response.should eq({
      result_code:   LDAP::Response::Code::Success,
      matched_dn:    "",
      error_message: "",
    })

    client.close
  end
end
