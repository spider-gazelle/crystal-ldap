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
    Extensible

    # This is primarily used for Microsoft Active Directory to compare GUID values
    BinaryComparison
  end

  def initialize(@operation : Type, @left : String, @right : String)
  end

  def self.equal(object : String, value)
    self.new(Type::Equal, object, value.to_s)
  end


  def to_ber
    case @operation
    when Type::Equal
      if @right == "*" # presence test
        @left.to_s.to_ber_contextspecific(7)
      elsif @right =~ /[*]/ # substring
        # Parsing substrings is a little tricky. We use String#split to
        # break a string into substrings delimited by the * (star)
        # character. But we also need to know whether there is a star at the
        # head and tail of the string, so we use a limit parameter value of
        # -1: "If negative, there is no limit to the number of fields
        # returned, and trailing null fields are not suppressed."
        #
        # 20100320 AZ: This is much simpler than the previous verison. Also,
        # unnecessary regex escaping has been removed.

        ary = @right.split(/[*]+/, -1)

        if ary.first.empty?
          first = nil
          ary.shift
        else
          first = unescape(ary.shift).to_ber_contextspecific(0)
        end

        if ary.last.empty?
          last = nil
          ary.pop
        else
          last = unescape(ary.pop).to_ber_contextspecific(2)
        end

        seq = ary.map { |e| unescape(e).to_ber_contextspecific(1) }
        seq.unshift first if first
        seq.push last if last

        [@left.to_s.to_ber, seq.to_ber].to_ber_contextspecific(4)
      else # equality
        [@left.to_s.to_ber, unescape(@right).to_ber].to_ber_contextspecific(3)
      end
    when Type::BinaryComparison
      # make sure data is not forced to UTF-8
      [@left.to_s.to_ber, unescape(@right).to_ber_bin].to_ber_contextspecific(3)
    when Type::Extensible
      seq = [] of BER

      unless @left =~ /^([-;\w]*)(:dn)?(:(\w+|[.\w]+))?$/
        raise Net::LDAP::BadAttributeError, "Bad attribute #{@left}"
      end
      type, dn, rule = $1, $2, $4

      seq << rule.to_ber_contextspecific(1) unless rule.to_s.empty? # matchingRule
      seq << type.to_ber_contextspecific(2) unless type.to_s.empty? # type
      seq << unescape(@right).to_ber_contextspecific(3) # matchingValue
      seq << "1".to_ber_contextspecific(4) unless dn.to_s.empty? # dnAttributes

      seq.to_ber_contextspecific(9)
    when Type::GreaterThanOrEqual
      [@left.to_s.to_ber, unescape(@right).to_ber].to_ber_contextspecific(5)
    when Type::LessThanOrEqual
      [@left.to_s.to_ber, unescape(@right).to_ber].to_ber_contextspecific(6)
    when Type::NotEqual
      [self.class.eq(@left, @right).to_ber].to_ber_contextspecific(2)
    when Type::And
      ary = [@left.coalesce(:and), @right.coalesce(:and)].flatten
      ary.map(&:to_ber).to_ber_contextspecific(0)
    when Type::Or
      ary = [@left.coalesce(:or), @right.coalesce(:or)].flatten
      ary.map(&:to_ber).to_ber_contextspecific(1)
    when Type::Not
      [@left.to_ber].to_ber_contextspecific(2)
    end
  end
end
