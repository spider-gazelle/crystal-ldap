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
    if token = scanner.scan(/[-\w:.]*[\w]/)
      scanner.scan(/\s*/)
      if op = scanner.scan(/<=|>=|!=|:=|=/)
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
            # when ":="
            #  Filter.ex(token, value)
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
end
