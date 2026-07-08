module LDAP
  # A single search result: its distinguished name plus its attributes.
  #
  # Attribute values are stored as raw `Bytes` — LDAP octet strings are not
  # necessarily UTF-8 (e.g. `objectGUID`, `userCertificate`). Use `#[]` for the
  # common text case (decoded as a String) and `#bytes` for binary attributes.
  struct Entry
    getter dn : String
    getter attributes : Hash(String, Array(Bytes))

    def initialize(@dn : String, @attributes : Hash(String, Array(Bytes)))
    end

    # The values of *key* decoded as strings. Raises `KeyError` if absent.
    def [](key : String) : Array(String)
      attributes[key].map { |value| String.new(value) }
    end

    # The values of *key* decoded as strings, or `nil` if the attribute is absent.
    def []?(key : String) : Array(String)?
      attributes[key]?.try &.map { |value| String.new(value) }
    end

    # The raw byte values of *key* (for binary attributes). Raises if absent.
    def bytes(key : String) : Array(Bytes)
      attributes[key]
    end

    # The attribute names present on this entry.
    def keys : Array(String)
      attributes.keys
    end

    def has_attribute?(key : String) : Bool
      attributes.has_key?(key)
    end
  end
end
