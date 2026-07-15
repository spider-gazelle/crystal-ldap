{% skip_file unless flag?(:integration) %}
require "./integration_helper"

describe "LDAP integration — bind" do
  it "binds as the directory admin" do
    client = Integration.bound_admin
    client.closed?.should be_false
    client.close
  end

  it "raises AuthError on a wrong password" do
    client = Integration.client
    expect_raises(LDAP::Client::AuthError) do
      client.authenticate(Integration::ADMIN_DN, "wrong-password")
    end
  end
end
