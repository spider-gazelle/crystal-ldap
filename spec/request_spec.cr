require "./spec_helper"

describe LDAP::Request do
  # RFC 4511 §4.1.1.1: "The message ID of zero is reserved for unsolicited
  # notifications and MUST NOT be used in any other request." So the first
  # client request must use a non-zero message ID.
  describe "#next_message_id" do
    it "starts at 1, never 0 (0 is reserved per RFC 4511 §4.1.1.1)" do
      req = LDAP::Request.new
      req.next_message_id.should eq(1)
    end

    it "increments monotonically" do
      req = LDAP::Request.new
      req.next_message_id.should eq(1)
      req.next_message_id.should eq(2)
      req.next_message_id.should eq(3)
    end
  end

  describe "#encode_paged_control" do
    it "encodes an RFC 2696 paged-results control (oid, non-critical, {size, cookie})" do
      req = LDAP::Request.new
      control = req.encode_paged_control(500, Bytes.empty)

      fields = control.children
      fields[0].get_string.should eq("1.2.840.113556.1.4.319") # PAGED_RESULTS
      fields[1].get_boolean.should be_false                    # criticality

      # controlValue is an OCTET STRING wrapping SEQUENCE { size, cookie }
      inner = IO::Memory.new(fields[2].get_string.to_slice).read_bytes(ASN1::BER)
      inner.children[0].get_integer.to_i.should eq(500) # page size
      inner.children[1].get_string.should eq("")        # empty cookie
    end

    it "round-trips a binary cookie verbatim" do
      req = LDAP::Request.new
      cookie = Bytes[0x00, 0xFF, 0x10, 0x80]
      control = req.encode_paged_control(1000, cookie)

      inner = IO::Memory.new(control.children[2].get_string.to_slice).read_bytes(ASN1::BER)
      inner.children[1].get_string.to_slice.should eq(cookie)
    end
  end

  describe "#search controls" do
    it "wraps controls as [0] SEQUENCE OF Control (context tag 0xA0)" do
      built = LDAP::Request.new.search(base: "dc=x", sort: "cn")
      msg = IO::Memory.new(built[1].to_slice).read_bytes(ASN1::BER)
      el = msg.children[2]
      el.to_slice[0].should eq(0xA0_u8)                                         # [0] constructed
      el.children.size.should eq(1)                                             # one Control (sort)
      el.children[0].children[0].get_string.should eq("1.2.840.113556.1.4.473") # SORT_REQUEST
    end

    it "emits no controls element when neither sort nor paging is given" do
      built = LDAP::Request.new.search(base: "dc=x")
      msg = IO::Memory.new(built[1].to_slice).read_bytes(ASN1::BER)
      controls = msg.children.size == 3 ? msg.children[2] : nil
      controls.should be_nil
    end

    it "adds the paged control when page_size is set" do
      built = LDAP::Request.new.search(base: "dc=x", page_size: 250, cookie: Bytes[0x01, 0x02])
      msg = IO::Memory.new(built[1].to_slice).read_bytes(ASN1::BER)
      el = msg.children[2]
      el.children.size.should eq(1)
      el.children[0].children[0].get_string.should eq("1.2.840.113556.1.4.319") # PAGED_RESULTS
      inner = IO::Memory.new(el.children[0].children[2].get_string.to_slice).read_bytes(ASN1::BER)
      inner.children[0].get_integer.to_i.should eq(250)
      inner.children[1].get_string.to_slice.should eq(Bytes[0x01, 0x02])
    end

    it "composes sort and paged in one controls sequence" do
      built = LDAP::Request.new.search(base: "dc=x", sort: "cn", page_size: 100)
      msg = IO::Memory.new(built[1].to_slice).read_bytes(ASN1::BER)
      el = msg.children[2]
      el.to_slice[0].should eq(0xA0_u8) # [0] constructed
      el.children.size.should eq(2)
      oids = el.children.map(&.children.[0].get_string)
      oids.should contain("1.2.840.113556.1.4.473") # sort
      oids.should contain("1.2.840.113556.1.4.319") # paged
    end

    it "wraps a pre-encoded BER sort control in [0] SEQUENCE OF Control" do
      control = LDAP::Request.new.encode_sort_controls("cn")
      built = LDAP::Request.new.search(base: "dc=x", sort: control)
      msg = IO::Memory.new(built[1].to_slice).read_bytes(ASN1::BER)
      el = msg.children[2]
      el.to_slice[0].should eq(0xA0_u8) # [0] constructed
      el.children.size.should eq(1)
      el.children[0].children[0].get_string.should eq("1.2.840.113556.1.4.473") # SORT_REQUEST
    end
  end
end
