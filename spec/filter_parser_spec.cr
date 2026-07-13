require "./spec_helper"

describe LDAP::Request::FilterParser do
  it "should parse a basic filter" do
    parsed_filter = LDAP::Request::FilterParser.parse("(uid=einstein)")
    direct_filter = LDAP::Request::Filter.equal("uid", "einstein")

    parsed_filter.to_slice.should eq(direct_filter.to_slice)
  end

  it "should parse a variety of filters" do
    # test multibyte characters
    LDAP::Request::FilterParser.parse("(cn=名前)").to_slice
      .should eq(LDAP::Request::Filter.equal("cn", "名前").to_slice)
    # test brackets
    LDAP::Request::FilterParser.parse("(cn=[{something}])").to_slice
      .should eq(LDAP::Request::Filter.equal("cn", "[{something}]").to_slice)
    # test slashes
    LDAP::Request::FilterParser.parse("(departmentNumber=FOO//BAR/FOO)").to_slice
      .should eq(LDAP::Request::Filter.equal("departmentNumber", "FOO//BAR/FOO").to_slice)
    # test colons
    LDAP::Request::FilterParser.parse("(ismemberof=cn=edu:berkeley:app:calmessages:deans,ou=campus groups,dc=berkeley,dc=edu)").to_slice
      .should eq(LDAP::Request::Filter.equal("ismemberof", "cn=edu:berkeley:app:calmessages:deans,ou=campus groups,dc=berkeley,dc=edu").to_slice)
  end

  it "parses an approx (~=) filter" do
    LDAP::Request::FilterParser.parse("(cn~=smith)").to_slice
      .should eq(LDAP::Request::Filter.approx("cn", "smith").to_slice)
  end

  it "parses an extensible (:=) filter with attribute only" do
    LDAP::Request::FilterParser.parse("(cn:=smith)").to_slice
      .should eq(LDAP::Request::Filter.extensible("smith", attribute: "cn").to_slice)
  end

  it "parses an extensible filter with dnAttributes" do
    LDAP::Request::FilterParser.parse("(cn:dn:=smith)").to_slice
      .should eq(LDAP::Request::Filter.extensible("smith", attribute: "cn", dn_attributes: true).to_slice)
  end

  it "parses an extensible filter with a matching rule" do
    LDAP::Request::FilterParser.parse("(cn:caseIgnoreMatch:=smith)").to_slice
      .should eq(LDAP::Request::Filter.extensible("smith", attribute: "cn", rule: "caseIgnoreMatch").to_slice)
  end

  it "parses an extensible filter with dn and a matching rule" do
    LDAP::Request::FilterParser.parse("(cn:dn:caseIgnoreMatch:=smith)").to_slice
      .should eq(LDAP::Request::Filter.extensible("smith", attribute: "cn", rule: "caseIgnoreMatch", dn_attributes: true).to_slice)
  end

  it "parses an extensible filter with a rule and no attribute" do
    LDAP::Request::FilterParser.parse("(:caseIgnoreMatch:=smith)").to_slice
      .should eq(LDAP::Request::Filter.extensible("smith", rule: "caseIgnoreMatch").to_slice)
  end

  it "raises ArgumentError on an extensible LHS with neither attribute nor rule" do
    expect_raises(ArgumentError) do
      LDAP::Request::FilterParser.parse("(:dn:=smith)")
    end
  end

  it "rejects an extensible LHS with more than one matching-rule segment" do
    expect_raises(LDAP::Request::FilterParser::FilterSyntaxInvalidError) do
      LDAP::Request::FilterParser.parse("(cn:foo:bar:=smith)")
    end
  end

  it "treats a case-insensitive dn marker as dnAttributes" do
    LDAP::Request::FilterParser.parse("(cn:DN:=smith)").to_slice
      .should eq(LDAP::Request::Filter.extensible("smith", attribute: "cn", dn_attributes: true).to_slice)
  end
end
