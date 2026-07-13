require "string_scanner"
require "./filter"

class LDAP::Request::FilterParser
  class FilterSyntaxInvalidError < Error; end

  getter filter : Filter

  def initialize(ldap_filter : String)
    filter = parse(StringScanner.new(ldap_filter))
    raise FilterSyntaxInvalidError.new("Invalid filter syntax") unless filter
    @filter = filter
  end

  def self.parse(filter : String)
    self.new(filter).filter
  end

  # Parsing tries to parse a standalone expression first. If that fails,
  # it tries to parse a parenthesized expression.
  def parse(scanner)
    parse_filter_branch(scanner) || parse_paren_expression(scanner)
  end

  # This parses a given expression inside of parentheses.
  def parse_filter_branch(scanner)
    scanner.scan(/\s*/)
    # The trailing [\w] makes this stop on a word char, i.e. just before `:=`,
    # so an extensible LHS (which may contain ':') is captured whole and split later.
    if token = scanner.scan(/[-\w:.]*[\w]/)
      scanner.scan(/\s*/)
      if op = scanner.scan(/<=|>=|!=|~=|:=|=/)
        scanner.scan(/\s*/)
        if value = scanner.scan(/(?:[-\[\]{}\w*.+\/:@=,#\$%&!'^~\s\xC3\x80-\xCA\xAF]|[^\x00-\x7F]|\\[a-fA-F\d]{2})+/)
          # 20100313 AZ: Assumes that "(uid=george*)" is the same as
          # "(uid=george* )". The standard doesn't specify, but I can find
          # no examples that suggest otherwise.
          value = value.strip
          case op
          when "="
            Filter.equal(token, value, escaped: true)
          when "!="
            Filter.not_equal(token, value, escaped: true)
          when "<="
            Filter.less_than(token, value)
          when ">="
            Filter.greater_than(token, value)
          when "~="
            Filter.approx(token, value, escaped: true)
          when ":="
            Filter.extensible(Filter.unescape(value, true), **parse_extensible_lhs(token))
          else
            raise FilterSyntaxInvalidError.new("unsupported operation #{op}")
          end
        end
      end
    end
  end

  def parse_paren_expression(scanner)
    if scanner.scan(/\s*\(\s*/)
      expr = if scanner.scan(/\s*\&\s*/)
               merge_branches(:&, scanner)
             elsif scanner.scan(/\s*\|\s*/)
               merge_branches(:|, scanner)
             elsif scanner.scan(/\s*\!\s*/)
               br = parse_paren_expression(scanner)
               ~br if br
             else
               parse_filter_branch(scanner)
             end

      if expr && scanner.scan(/\s*\)\s*/)
        expr
      end
    end
  end

  # Join ("&") and intersect ("|") operations are presented in branches.
  # That is, the expression <tt>(&(test1)(test2)</tt> has two branches:
  # test1 and test2. Each of these is parsed separately and then pushed
  # into a branch array for filter merging using the parent operation.
  #
  # This method calls #parse_branches to generate the branch list and then
  # merges them into a single Filter tree by calling the provided
  # operation.
  def merge_branches(op, scanner)
    filter = nil
    branches = parse_branches(scanner)

    if branches.size >= 1
      filter = branches.shift
      loop do
        break if branches.empty?

        case op
        when :&
          filter = filter & branches.shift
        when :|
          filter = filter | branches.shift
        else
          raise FilterSyntaxInvalidError.new("unsupported branch merge #{op}")
        end
      end
    end

    filter
  end

  # This method parses the branch text out into an array of filter objects.
  def parse_branches(scanner)
    branches = [] of Filter
    loop do
      branch = parse_paren_expression(scanner)
      break unless branch

      branches << branch
    end
    branches
  end

  # RFC 4515 extensible LHS: attr[":dn"][":" rule]  or  ":" [dn ":"] rule.
  # The `token` regex includes ':' so it already absorbed the whole LHS; split it.
  # A colon-separated "dn" is the reserved dnAttributes flag, never a matching rule.
  private def parse_extensible_lhs(token : String)
    parts = token.split(':')
    attribute = parts.shift
    attribute = nil if attribute.empty?
    dn_attributes = false
    rule = nil
    parts.each do |part|
      if part.compare("dn", case_insensitive: true) == 0
        # RFC 4515 ABNF string literals are case-insensitive; "dn" is the reserved
        # dnAttributes flag, never a matching rule.
        dn_attributes = true
      elsif rule.nil?
        rule = part
      else
        # More than one matching-rule segment is malformed — reject rather than
        # silently drop one and build a filter that differs from the input.
        raise FilterSyntaxInvalidError.new("invalid extensible match LHS: #{token.inspect}")
      end
    end
    {attribute: attribute, rule: rule, dn_attributes: dn_attributes}
  end
end
