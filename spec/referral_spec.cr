require "./spec_helper"

# A SearchResultDone (tag 5) with result *code* and, when *uris* is non-empty, a
# referral [3] field.
private def referral_done(id : Int32, uris : Array(String), code : Int32) : Bytes
  fields = [
    LDAP::BER.new.set_integer(code, LDAP::UniversalTags::Enumerated),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
  ] of LDAP::BER
  unless uris.empty?
    fields << LDAP.context_sequence(uris.map { |uri| LDAP::BER.new.set_string(uri, LDAP::UniversalTags::OctetString) }, 3)
  end
  op = LDAP.app_sequence(fields, LDAP::Tag::SearchResult)
  LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
end

# A SearchResultReference (tag 19) continuation message carrying *uris*.
private def continuation_ref(id : Int32, uris : Array(String)) : Bytes
  op = LDAP.app_sequence(uris.map { |uri| LDAP::BER.new.set_string(uri, LDAP::UniversalTags::OctetString) }, LDAP::Tag::SearchResultReferral)
  LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
end

# A SearchResultEntry (tag 4) for *dn* with no attributes.
private def entry_msg(id : Int32, dn : String) : Bytes
  op = LDAP.app_sequence({
    LDAP::BER.new.set_string(dn, LDAP::UniversalTags::OctetString),
    LDAP.sequence([] of LDAP::BER),
  }, LDAP::Tag::SearchReturnedData)
  LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
end

private def bytes_concat(*parts : Bytes) : Bytes
  io = IO::Memory.new
  parts.each { |part| io.write part }
  io.to_slice
end

# An operation result (tag *op_tag*) with resultCode referral (10) + a [3] URL.
private def op_referral(id : Int32, op_tag : LDAP::Tag) : Bytes
  op = LDAP.app_sequence({
    LDAP::BER.new.set_integer(10, LDAP::UniversalTags::Enumerated),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
    LDAP::BER.new.set_string("", LDAP::UniversalTags::OctetString),
    LDAP.context_sequence({LDAP::BER.new.set_string("ldap://b/", LDAP::UniversalTags::OctetString)}, 3),
  }, op_tag)
  LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
end

describe LDAP::Client do
  describe "#search referrals" do
    it "raises ReferralError with the [3] URLs on a referral result code" do
      socket = FakeSocket.new { |id| referral_done(id, ["ldap://b/dc=x"], code: 10) }
      client = LDAP::Client.new(socket)

      ex = expect_raises(LDAP::Client::ReferralError) do
        client.search(base: "dc=x")
      end
      ex.referrals.should eq(["ldap://b/dc=x"])
      ex.result_code.should eq(LDAP::Response::Code::Referral)
    end

    it "raises ReferralError carrying entries and continuation URLs on a successful search" do
      socket = FakeSocket.new do |id|
        bytes_concat(
          entry_msg(id, "uid=a,dc=x"),
          continuation_ref(id, ["ldap://b/ou=sub,dc=x"]),
          referral_done(id, [] of String, code: 0),
        )
      end
      client = LDAP::Client.new(socket)

      ex = expect_raises(LDAP::Client::ReferralError) do
        client.search(base: "dc=x")
      end
      ex.entries.map(&.dn).should eq(["uid=a,dc=x"])
      ex.referrals.should eq(["ldap://b/ou=sub,dc=x"])
    end

    it "raises ReferralError from the streaming (block) form on a continuation reference" do
      socket = FakeSocket.new do |id|
        bytes_concat(
          entry_msg(id, "uid=a,dc=x"),
          continuation_ref(id, ["ldap://b/ou=sub,dc=x"]),
          referral_done(id, [] of String, code: 0),
        )
      end
      client = LDAP::Client.new(socket)

      yielded = [] of String
      ex = expect_raises(LDAP::Client::ReferralError) do
        client.search(base: "dc=x", page_size: 10) { |entry| yielded << entry.dn }
      end
      yielded.should eq(["uid=a,dc=x"]) # entry streamed before the raise
      ex.referrals.should eq(["ldap://b/ou=sub,dc=x"])
    end
  end

  describe "#expect_result / #compare referrals" do
    it "modify raises ReferralError on a referral result code" do
      socket = FakeSocket.new { |id| op_referral(id, LDAP::Tag::ModifyResponse) }
      client = LDAP::Client.new(socket)
      ex = expect_raises(LDAP::Client::ReferralError) do
        client.modify("cn=a,dc=x", [LDAP::Modification.replace("sn", "b")])
      end
      ex.referrals.should eq(["ldap://b/"])
    end

    it "compare raises ReferralError on a referral result code" do
      socket = FakeSocket.new { |id| op_referral(id, LDAP::Tag::CompareResponse) }
      client = LDAP::Client.new(socket)
      ex = expect_raises(LDAP::Client::ReferralError) do
        client.compare("cn=a,dc=x", "sn", "b")
      end
      ex.referrals.should eq(["ldap://b/"])
    end
  end
end
