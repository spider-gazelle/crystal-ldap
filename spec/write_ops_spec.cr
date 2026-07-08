require "./spec_helper"

# Decodes a built request's LDAPMessage back into {message_id, protocol-op BER}
# so builder specs can assert structure without hand-computing every byte.
private def decode_request(packet : LDAP::BER)
  children = packet.children
  {children[0].get_integer.to_i, children[1]}
end

# An LDAPResult-bearing response (Add/Delete/Modify/ModifyDN share this shape).
private def result_response(id : Int32, tag : LDAP::Tag, code : Int32, dn = "", msg = "") : Bytes
  op = LDAP.app_sequence({
    LDAP::BER.new.set_integer(code, LDAP::UniversalTags::Enumerated),
    LDAP::BER.new.set_string(dn, LDAP::UniversalTags::OctetString),
    LDAP::BER.new.set_string(msg, LDAP::UniversalTags::OctetString),
  }, tag)
  LDAP.sequence({LDAP::BER.new.set_integer(id), op}).to_slice
end

describe LDAP::Request do
  describe "#delete" do
    it "encodes DelRequest as a primitive [APPLICATION 10] carrying the DN" do
      # 30 09  02 01 01  4A 04 6F 75 3D 78
      #  SEQ    msgID=1    [APP 10] primitive "ou=x"
      _, packet = LDAP::Request.new.delete("ou=x")
      packet.to_slice.should eq(Bytes[0x30, 0x09, 0x02, 0x01, 0x01, 0x4A, 0x04, 0x6F, 0x75, 0x3D, 0x78])
    end
  end

  describe "#add" do
    # Byte-exact anchor (computed by hand from RFC 4511 §4.7 / X.690), independent
    # of the decoder — pins the constructed [APPLICATION 8] tag (0x68) and the
    # SET-OF-values tag (0x31), which the decode-based check below cannot isolate.
    it "encodes a minimal AddRequest to exact bytes" do
      _, packet = LDAP::Request.new.add("o=x", {"cn" => ["A"]})
      packet.to_slice.should eq(Bytes[
        0x30, 0x17,                   # SEQUENCE (LDAPMessage), len 23
        0x02, 0x01, 0x01,             #   messageID INTEGER 1
        0x68, 0x12,                   #   [APPLICATION 8] constructed (AddRequest), len 18
        0x04, 0x03, 0x6F, 0x3D, 0x78, #     entry "o=x"
        0x30, 0x0B,                   #     attributes SEQUENCE OF, len 11
        0x30, 0x09,                   #       attribute SEQUENCE, len 9
        0x04, 0x02, 0x63, 0x6E,       #         type "cn"
        0x31, 0x03,                   #         vals SET OF, len 3
        0x04, 0x01, 0x41,             #           "A"
      ])
    end

    it "encodes AddRequest [APPLICATION 8] with the entry DN and attribute list" do
      _, packet = LDAP::Request.new.add("cn=a,dc=x", {"cn" => ["Alice"], "sn" => ["A", "B"]})
      _, op = decode_request(packet)
      op.tag_number.to_i.should eq(LDAP::Tag::AddRequest.value)

      entry, attributes = op.children
      entry.get_string.should eq("cn=a,dc=x")

      attrs = attributes.children
      attrs.size.should eq(2)
      attrs[0].children[0].get_string.should eq("cn")
      attrs[0].children[1].children.map(&.get_string).should eq(["Alice"])
      attrs[1].children[0].get_string.should eq("sn")
      attrs[1].children[1].children.map(&.get_string).should eq(["A", "B"])
    end
  end
end

describe LDAP::Modification do
  it "builds add/delete/replace via named constructors" do
    LDAP::Modification.add("objectClass", "person", "top").operation.add?.should be_true
    LDAP::Modification.replace("mail", "a@b").values.should eq(["a@b"])

    deletion = LDAP::Modification.delete("telephoneNumber")
    deletion.operation.delete?.should be_true
    deletion.type.should eq("telephoneNumber")
    deletion.values.should be_empty
  end

  it "maps operations to the RFC 4511 §4.6 ENUMERATED values" do
    LDAP::ModifyOperation::Add.value.should eq(0)
    LDAP::ModifyOperation::Delete.value.should eq(1)
    LDAP::ModifyOperation::Replace.value.should eq(2)
  end
end

describe LDAP::Request do
  describe "#modify" do
    it "encodes ModifyRequest [APPLICATION 6] with the object DN and changes" do
      _, packet = LDAP::Request.new.modify("cn=a,dc=x", [
        LDAP::Modification.replace("mail", "a@b"),
        LDAP::Modification.delete("phone"),
      ])
      _, op = decode_request(packet)
      op.tag_number.to_i.should eq(LDAP::Tag::ModifyRequest.value)

      object, changes = op.children
      object.get_string.should eq("cn=a,dc=x")

      change_list = changes.children
      change_list.size.should eq(2)

      operation, modification = change_list[0].children
      operation.get_integer.should eq(LDAP::ModifyOperation::Replace.value)
      modification.children[0].get_string.should eq("mail")
      modification.children[1].children.map(&.get_string).should eq(["a@b"])

      change_list[1].children[0].get_integer.should eq(LDAP::ModifyOperation::Delete.value)
      change_list[1].children[1].children[1].children.should be_empty
    end
  end
end

describe LDAP::Client do
  describe "#modify" do
    it "returns self on a successful modify" do
      socket = FakeSocket.new { |id| result_response(id, LDAP::Tag::ModifyResponse, 0) }
      client = LDAP::Client.new(socket)
      client.modify("cn=a,dc=x", [LDAP::Modification.replace("mail", "a@b")]).should be(client)
    end

    it "raises OperationError on a failed modify" do
      socket = FakeSocket.new { |id| result_response(id, LDAP::Tag::ModifyResponse, LDAP::Response::Code::NoSuchObject.value, "", "missing") }
      client = LDAP::Client.new(socket)
      err = expect_raises(LDAP::Client::OperationError) { client.modify("cn=a,dc=x", [LDAP::Modification.delete("mail")]) }
      err.result_code.no_such_object?.should be_true
    end
  end

  describe "#delete" do
    it "returns self on a successful delete" do
      socket = FakeSocket.new { |id| result_response(id, LDAP::Tag::DeleteResponse, 0) }
      client = LDAP::Client.new(socket)
      client.delete("ou=x,dc=example,dc=com").should be(client)
    end

    it "raises OperationError on a failed delete" do
      socket = FakeSocket.new { |id| result_response(id, LDAP::Tag::DeleteResponse, LDAP::Response::Code::NoSuchObject.value, "", "no such object") }
      client = LDAP::Client.new(socket)
      err = expect_raises(LDAP::Client::OperationError) { client.delete("ou=missing") }
      err.result_code.no_such_object?.should be_true
    end
  end

  describe "#add" do
    it "returns self on a successful add" do
      socket = FakeSocket.new { |id| result_response(id, LDAP::Tag::AddResponse, 0) }
      client = LDAP::Client.new(socket)
      client.add("cn=a,dc=x", {"cn" => ["Alice"]}).should be(client)
    end

    it "raises OperationError on a failed add" do
      socket = FakeSocket.new { |id| result_response(id, LDAP::Tag::AddResponse, LDAP::Response::Code::EntryAlreadyExists.value, "", "exists") }
      client = LDAP::Client.new(socket)
      err = expect_raises(LDAP::Client::OperationError) { client.add("cn=a,dc=x", {"cn" => ["Alice"]}) }
      err.result_code.entry_already_exists?.should be_true
    end
  end
end
