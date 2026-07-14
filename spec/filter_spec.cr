require "./spec_helper"

private alias Filter = LDAP::Request::Filter

describe LDAP::Request::Filter do
  describe "boolean composition" do
    it "conjoin / & encode an and [0] of both filters" do
      left = Filter.equal("cn", "a")
      right = Filter.equal("sn", "b")

      ber = Filter.conjoin(left, right).to_ber
      ber.to_slice[0].should eq(0xA0_u8) # and [0] context-constructed
      ber.children.size.should eq(2)
      (left & right).to_slice.should eq(ber.to_slice)
    end

    it "disjoin / | encode an or [1] of both filters" do
      left = Filter.equal("cn", "a")
      right = Filter.equal("sn", "b")

      ber = Filter.disjoin(left, right).to_ber
      ber.to_slice[0].should eq(0xA1_u8) # or [1] context-constructed
      ber.children.size.should eq(2)
      (left | right).to_slice.should eq(ber.to_slice)
    end
  end

  describe ".approx" do
    it "encodes an approxMatch [8] with attribute and value" do
      filter = Filter.approx("cn", "smith")
      ber = filter.to_ber
      ber.to_slice[0].should eq(0xA8_u8)            # [8] context-constructed
      ber.children[0].get_string.should eq("cn")    # attributeDesc (universal octet string)
      ber.children[1].get_string.should eq("smith") # assertionValue
      filter.operation.should eq(Filter::Type::Approx)
    end
  end

  describe ".extensible" do
    it "encodes attribute-only as [9] { [2] type, [3] value }" do
      ber = Filter.extensible("smith", attribute: "cn").to_ber
      ber.to_slice[0].should eq(0xA9_u8)                             # [9] context-constructed
      ber.children.map(&.to_slice.[0]).should eq([0x82_u8, 0x83_u8]) # [2] type, [3] value
      String.new(ber.children[0].get_bytes).should eq("cn")
      String.new(ber.children[1].get_bytes).should eq("smith")
    end

    it "encodes rule-only as [9] { [1] rule, [3] value }" do
      ber = Filter.extensible("smith", rule: "caseIgnoreMatch").to_ber
      ber.children.map(&.to_slice.[0]).should eq([0x81_u8, 0x83_u8]) # [1] rule, [3] value
      String.new(ber.children[0].get_bytes).should eq("caseIgnoreMatch")
    end

    it "encodes the full form with dnAttributes [4] TRUE" do
      ber = Filter.extensible("smith", attribute: "cn", rule: "caseIgnoreMatch", dn_attributes: true).to_ber
      ber.children.map(&.to_slice.[0]).should eq([0x81_u8, 0x82_u8, 0x83_u8, 0x84_u8])
      ber.children[3].get_bytes.should eq(Bytes[0xFF]) # dnAttributes = TRUE
    end

    it "omits [4] when dn_attributes is false (BER DEFAULT FALSE)" do
      ber = Filter.extensible("smith", attribute: "cn").to_ber
      ber.children.map(&.to_slice.[0]).includes?(0x84_u8).should be_false
    end

    it "raises when neither attribute nor rule is given" do
      expect_raises(ArgumentError) { Filter.extensible("smith") }
    end
  end
end
