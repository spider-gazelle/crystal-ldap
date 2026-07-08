require "./spec_helper"

describe LDAP::Entry do
  guid = Bytes[0x00, 0xff, 0xfe, 0x80]
  entry = LDAP::Entry.new(
    "uid=a,dc=example,dc=com",
    {
      "cn"         => ["Alice".to_slice],
      "mail"       => ["a@x".to_slice, "a@y".to_slice],
      "objectGUID" => [guid],
    }
  )

  it "exposes the dn separately from the attributes" do
    entry.dn.should eq("uid=a,dc=example,dc=com")
    entry.keys.should contain("cn")
    entry.keys.should_not contain("dn")
  end

  it "decodes attribute values as strings via #[]" do
    entry["cn"].should eq(["Alice"])
    entry["mail"].should eq(["a@x", "a@y"])
  end

  it "returns the raw bytes via #bytes" do
    entry.bytes("objectGUID").first.should eq(guid)
  end

  it "returns nil from #[]? for a missing attribute" do
    entry["mail"]?.should eq(["a@x", "a@y"])
    entry["missing"]?.should be_nil
  end

  it "raises KeyError from #[] for a missing attribute" do
    expect_raises(KeyError) { entry["missing"] }
  end

  it "answers #has_attribute?" do
    entry.has_attribute?("cn").should be_true
    entry.has_attribute?("missing").should be_false
  end
end
