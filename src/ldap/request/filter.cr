require "../request"

class LDAP::Request::Filter
  enum Type
    NotEqual
    Equal
    GreaterThanOrEqual
    LessThanOrEqual
    And
    Or
    Not

    # TODO:: Implement this
    Extensible
  end

  ESCAPES = {
    "\0" => "\\00", # NUL            = %x00 ; null character
    "*"  => "\\2A", # ASTERISK       = %x2A ; asterisk ("*")
    "("  => "\\28", # LPARENS        = %x28 ; left parenthesis ("(")
    ")"  => "\\29", # RPARENS        = %x29 ; right parenthesis (")")
    "\\" => "\\5C", # ESC            = %x5C ; esc (or backslash) ("\")
  }
  # Compiled character class regexp using the keys from the above hash.
  ESCAPE_RE = Regex.new(String.build { |str|
    str << "["
    ESCAPES.keys.each { |e| str << Regex.escape(e) }
    str << "]"
  })

  # Escape a string for use in an LDAP filter
  def self.escape(string : String) : String
    string.gsub(ESCAPE_RE) { |char| ESCAPES[char] }
  end

  def self.unescape(value : String, escaped : Bool = false) : String
    escaped ? value.gsub(/\\([a-fA-F\d]{2})/) { String.new($1.hexbytes) } : value
  end

  def initialize(@operation : Type, @filter : BER)
  end

  getter operation : Type

  def to_ber
    @filter
  end

  def to_slice
    to_ber.to_slice
  end

  def self.equal(object : String, value, escaped : Bool = false)
    value = value.to_s
    if value == "*"
      self.new(Type::Equal, BER.new.set_string(object, 7, TagClass::ContextSpecific))
    elsif value =~ /[*]/
      ary = value.split(/[*]+/)

      if ary.first.empty?
        first = nil
        ary.shift
      else
        first = BER.new.set_string(unescape(ary.shift, escaped), 0, TagClass::ContextSpecific)
      end

      if ary.last.empty?
        last = nil
        ary.pop
      else
        last = BER.new.set_string(unescape(ary.pop, escaped), 2, TagClass::ContextSpecific)
      end

      seq = ary.map { |e| BER.new.set_string(unescape(e, escaped), 1, TagClass::ContextSpecific) }
      seq.unshift first if first
      seq.push last if last
      seq = LDAP.sequence(seq)

      left = BER.new.set_string(object, UniversalTags::OctetString)
      self.new(Type::Equal, LDAP.context_sequence({left, seq}, 4))
    else
      left = BER.new.set_string(object, UniversalTags::OctetString)
      right = BER.new.set_string(unescape(value, escaped), UniversalTags::OctetString)
      self.new(Type::Equal, LDAP.context_sequence({left, right}, 3))
    end
  end

  def self.greater_than(object : String, value)
    left = BER.new.set_string(object, UniversalTags::OctetString)
    right = BER.new.set_string(value.to_s, UniversalTags::OctetString)
    self.new(Type::GreaterThanOrEqual, LDAP.context_sequence({left, right}, 5))
  end

  def self.less_than(object : String, value)
    left = BER.new.set_string(object, UniversalTags::OctetString)
    right = BER.new.set_string(value.to_s, UniversalTags::OctetString)
    self.new(Type::LessThanOrEqual, LDAP.context_sequence({left, right}, 6))
  end

  def self.not_equal(object : String, value, escaped : Bool = false)
    self.new(
      Type::NotEqual,
      LDAP.context_sequence({equal(object, value, escaped).to_ber}, 2)
    )
  end

  def self.negate(filter : Filter)
    self.new(Type::Not, LDAP.context_sequence({filter.to_ber}, 2))
  end

  def self.negate(filter : BER)
    self.new(Type::Not, LDAP.context_sequence({filter}, 2))
  end

  def self.join(left : BER, right : BER)
    self.new(Type::And, LDAP.context_sequence({left, right}, 0))
  end

  def self.join(left : Filter, right : Filter)
    self.new(Type::And, LDAP.context_sequence({left.to_ber, right.to_ber}, 0))
  end

  def self.intersect(left : BER, right : BER)
    self.new(Type::Or, LDAP.context_sequence({left, right}, 1))
  end

  def self.intersect(left : Filter, right : Filter)
    self.new(Type::Or, LDAP.context_sequence({left.to_ber, right.to_ber}, 1))
  end

  def self.begins(attribute : String, value)
    equal(attribute, "#{escape(value.to_s)}*", escaped: true)
  end

  def self.ends(attribute : String, value)
    equal(attribute, "*#{escape(value.to_s)}", escaped: true)
  end

  def self.contains(attribute : String, value)
    equal(attribute, "*#{escape(value.to_s)}*", escaped: true)
  end

  def self.present?(attribute : String)
    equal(attribute, "*")
  end

  # Joins two or more filters so that all conditions must be true.
  def &(filter)
    self.class.join(self, filter)
  end

  # Selects entries where either the left or right side are true.
  def |(filter)
    self.class.intersect(self, filter)
  end

  # Negates a filter.
  def ~
    self.class.negate(self)
  end
end
