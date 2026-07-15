{% skip_file unless flag?(:integration) %}
require "./integration_helper"

describe "LDAP integration — operations" do
  users_base = "ou=users,#{Integration::BASE}"
  test_ou = "ou=test,#{Integration::BASE}"

  # Idempotent clean slate: wipe ou=test (children first) then recreate it empty.
  before_each do
    admin = Integration.bound_admin
    begin
      begin
        admin.search(base: test_ou).each do |entry|
          admin.delete(entry.dn) unless entry.dn == test_ou
        end
        admin.delete(test_ou)
      rescue LDAP::Client::OperationError
        # ou=test absent — nothing to clean
      end
      admin.add(test_ou, {"objectClass" => ["organizationalUnit"], "ou" => ["test"]})
    ensure
      admin.close
    end
  end

  it "searches the seeded users with a filter" do
    admin = Integration.bound_admin
    dns = admin.search(base: users_base, filter: "(uid=user01)").map(&.dn)
    dns.should eq(["uid=user01,#{users_base}"])
    admin.close
  end

  it "adds, finds, modifies, compares, renames and deletes an entry" do
    admin = Integration.bound_admin
    dn = "uid=itest,#{test_ou}"

    admin.add(dn, {
      "objectClass" => ["inetOrgPerson"],
      "uid"         => ["itest"],
      "cn"          => ["Integration Test"],
      "sn"          => ["Before"],
    })
    admin.search(base: dn, scope: LDAP::SearchScope::BaseObject).map(&.dn).should eq([dn])

    admin.modify(dn, [LDAP::Modification.replace("sn", "After")])
    admin.compare(dn, "sn", "After").should be_true
    admin.compare(dn, "sn", "Before").should be_false

    admin.modify_dn(dn, "uid=itest2")
    new_dn = "uid=itest2,#{test_ou}"
    admin.search(base: new_dn, scope: LDAP::SearchScope::BaseObject).map(&.dn).should eq([new_dn])

    admin.delete(new_dn)
    admin.search(base: test_ou, filter: "(uid=itest2)").should be_empty
    admin.close
  end

  it "pages through the seeded users with a small page size" do
    admin = Integration.bound_admin
    dns = [] of String
    # SingleLevel: the five user entries directly under ou=users, not ou=users itself.
    admin.search(base: users_base, scope: LDAP::SearchScope::SingleLevel, page_size: 2) { |entry| dns << entry.dn }
    dns.size.should eq(5)
    admin.close
  end

  it "unbind closes the connection" do
    admin = Integration.bound_admin
    admin.unbind
    admin.closed?.should be_true
  end
end
