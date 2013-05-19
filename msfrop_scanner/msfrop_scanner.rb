#!/usr/bin/env ruby

msfbase = "/usr/local/share/metasploit-framework/lib"

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))

require 'fastlib'
require 'msfenv'
require 'rex'
require 'rex/ropbuilder'
require 'rexml/document'
require 'rex/ui/text/output/stdio'
require 'rex/ui/text/color'
require 'optparse'


ropbuilder = Rex::RopBuilder::RopCollect.new

opts = {}
color = true
verbose = false

opt = OptionParser.new
opt.banner = "Usage #{$PROGRAM_NAME} <option> [targets]"
opt.separator('')
opt.separator('Options:')

opt.on('-i', '--import [filename]', 'Import gadgets from previous collections') do |csv|
	opts[:import] = csv
end

opt.on('-x', '--xml [filename]', 'XML file to read set of needed gadgets from') do |csv|
	opts[:xml] = csv
end

opt.on('-v', '--verbose', 'Output very verbosely') do
	opts[:verbose] = true
end

opt.on_tail('-h', '--help', 'Show this message') do
	puts opt
	exit(1)
end

gadgets = []

begin
	opt.parse!
rescue OptionParser::InvalidOption
	puts "Invalid option, try -h for usage"
	exit(1)
end

if opts.empty? and (ARGV.empty? or ARGV.nil?)
	puts "no options"
	puts opt
	exit(1)
end

if opts[:import].nil?
	puts "The import file is required.  You can generate this with msfrop"
	puts opt
	exit(1)
else
	ropbuilder = Rex::RopBuilder::RopCollect.new()
	ropbuilder.print_msg("Importing gadgets from %bld%cya#{opts[:import]}\n", color)
	gadgets = ropbuilder.import(opts[:import])

	if opts[:verbose]
		gadgets.each do |gadget|
			ropbuilder.print_msg("gadget: %bld%cya#{gadget[:address]}%clr\n", color)
			ropbuilder.print_msg(gadget[:disasm] + "\n", color)
		end
	end

	ropbuilder.print_msg("Imported %grn#{gadgets.count}%clr gadgets\n", color)
end

if opts[:xml].nil?
	puts "The xml file is required."
	puts opt
	exit(1)
else
	xml = REXML::Document.new(File.read(opts[:xml]))
end


gadgets = []

xml.elements.each('db/rop') do |db|
	db.elements.each('gadgets/gadget') do |g|
		if g.attributes['offset']
			instr = g.text.gsub(/\s*;\s*/, "\n")
			sc = Metasm::Shellcode.assemble(Metasm::Ia32.new, instr).encode_string
			gadgets << { :type => 'offset', :text => g.text, :instr => instr, :bytecode => sc, :matches => ropbuilder.pattern_search(Regexp.escape(sc)) }

		elsif g.attributes['value']
			gadgets << { :type => 'value', :text => g.text, :value => g.attributes['value'] }
		elsif g.attributes['nop']
			gadgets << { :type => 'nop', :text => g.text, :value => g.attributes['nop'] }
		elsif g.attributes['junk']
			gadgets << { :type => 'junk', :text => g.text, :value => g.attributes['junk'] }
		elsif g.attributes['size']
			gadgets << { :type => 'size', :text => g.text, :value => g.attributes['size'] }
		elsif g.attributes['size_negate']
			gadgets << { :type => 'size_negate', :text => g.text, :value => g.attributes['size_negate'] }
		end
	end
end

gadgets.each do |gadget|
	if gadget[:type] == 'offset'
		match = gadget[:matches].first
		
		if match
			begin
				address = match[:addrs].first.gsub(/:$/, '').to_i(16) + match[:gadget][:raw].index(gadget[:bytecode])	
			rescue Exception => e
				address = 0xffffffff
			end
		else
			address = 0xffffffff
		end

		puts "<gadget offset='0x%08x'>#{gadget[:instr].gsub(/\n/, " ; ")}</gadget>" % address
	else
		puts "<gadget %-6s='#{gadget[:value]}'>#{gadget[:text]}</gadget>" % gadget[:type]
	end
		
end


