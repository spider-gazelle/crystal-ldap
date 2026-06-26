require "./helper"

# A result-bearing LDAPMessage { messageID, [APPLICATION tag] { resultCode, matchedDN, errorMessage } }.
private def result_message(id : Int32, tag : LDAP::Tag, code : Int32, dn = "", msg = "") : Bytes
  op = LDAP.app_sequence({
    LDAP::BER.new.set_integer(code, LDAP::UniversalTags::Enumerated),
    LDAP::BER.new.set_string(dn, LDAP::UniversalTags::OctetString),
    LDAP::BER.new.set_string(msg, LDAP::UniversalTags::OctetString),
  }, tag)
  LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
end

describe LDAP::Client::OperationError do
  it "carries the LDAP result fields and a composed message" do
    err = LDAP::Client::OperationError.new("modify", LDAP::Response::Code::NoSuchObject, "ou=x", "no such entry")
    err.result_code.should eq(LDAP::Response::Code::NoSuchObject)
    err.matched_dn.should eq("ou=x")
    err.error_message.should eq("no such entry")
    err.message.should eq("modify failed with NoSuchObject: no such entry")
  end

  it "is the parent of AuthError" do
    err = LDAP::Client::AuthError.new("bind", LDAP::Response::Code::InvalidCredentials, "", "bad creds")
    err.should be_a(LDAP::Client::OperationError)
    err.result_code.should eq(LDAP::Response::Code::InvalidCredentials)
  end
end

describe LDAP::Client do
  it "raises AuthError carrying the result code on a failed bind" do
    socket = FakeSocket.new { |id| result_message(id, LDAP::Tag::BindResult, LDAP::Response::Code::InvalidCredentials.value, "", "bad creds") }
    client = LDAP::Client.new(socket)
    err = expect_raises(LDAP::Client::AuthError) { client.authenticate("cn=admin", "wrong") }
    err.result_code.invalid_credentials?.should be_true
    err.error_message.should eq("bad creds")
  end

  it "raises OperationError (not AuthError) on a failed search" do
    socket = FakeSocket.new { |id| result_message(id, LDAP::Tag::SearchResult, LDAP::Response::Code::InsufficientAccessRights.value, "", "denied") }
    client = LDAP::Client.new(socket)
    err = expect_raises(LDAP::Client::OperationError) { client.search(base: "dc=x") }
    err.should_not be_a(LDAP::Client::AuthError)
    err.result_code.insufficient_access_rights?.should be_true
  end

  # SizeLimitExceeded/TimeLimitExceeded are "soft" search outcomes (partial
  # results), still in SEARCH_SUCCESS — they must NOT raise. Pins that kept set
  # before the later search-typing work revisits how partial results surface.
  it "does not raise when a search hits the size limit" do
    socket = FakeSocket.new { |id| result_message(id, LDAP::Tag::SearchResult, LDAP::Response::Code::SizeLimitExceeded.value) }
    client = LDAP::Client.new(socket)
    client.search(base: "dc=x").should eq([] of Hash(String, Array(String)))
  end
end
