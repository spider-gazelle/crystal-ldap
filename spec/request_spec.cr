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
end
