require "./helper"

describe LDAP::Request::FilterParser do
  it "should parse a basic filter" do
    parsed_filter = LDAP::Request::FilterParser.parse("(uid=einstein)")
    direct_filter = LDAP::Request::Filter.equal("uid", "einstein")

    parsed_filter.to_slice.should eq(direct_filter.to_slice)
  end

  it "should parse a variety of filters" do
    # test multibyte characters
    LDAP::Request::FilterParser.parse("(cn=名前)")
    # test brackets
    LDAP::Request::FilterParser.parse("(cn=[{something}])")
    # test slashes
    LDAP::Request::FilterParser.parse("(departmentNumber=FOO//BAR/FOO)")
    # test colons
    LDAP::Request::FilterParser.parse("(ismemberof=cn=edu:berkeley:app:calmessages:deans,ou=campus groups,dc=berkeley,dc=edu)")
  end
end
