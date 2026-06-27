module LDAP
  # A single change in a ModifyRequest. The enum values are the wire ENUMERATED
  # encoding (RFC 4511 §4.6).
  enum ModifyOperation
    Add     = 0
    Delete  = 1
    Replace = 2
  end

  # One modification applied to an attribute by `LDAP::Client#modify`. Build via
  # the named constructors:
  #
  #     LDAP::Modification.add("objectClass", "person")
  #     LDAP::Modification.replace("mail", "alice@example.com")
  #     LDAP::Modification.delete("telephoneNumber")   # whole attribute
  struct Modification
    getter operation : ModifyOperation
    getter type : String
    getter values : Array(String)

    def initialize(@operation : ModifyOperation, @type : String, @values : Array(String))
    end

    def self.add(type : String, *values : String) : self
      new(ModifyOperation::Add, type, values.to_a)
    end

    def self.delete(type : String) : self
      new(ModifyOperation::Delete, type, [] of String)
    end

    def self.delete(type : String, *values : String) : self
      new(ModifyOperation::Delete, type, values.to_a)
    end

    def self.replace(type : String) : self
      new(ModifyOperation::Replace, type, [] of String)
    end

    def self.replace(type : String, *values : String) : self
      new(ModifyOperation::Replace, type, values.to_a)
    end
  end
end
