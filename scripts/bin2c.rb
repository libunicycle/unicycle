#!/usr/bin/ruby
# SPDX-License-Identifier: MIT

require "optparse"

@section = ""
OptionParser.new do |opts|
  opts.on("", "--section=SECTION", "Section to put the variables") do |s|
    @section = "__attribute__((section(\"#{s}\"))) "
  end
end.parse!

def var_name(filename)
  "BLOB_" + File.basename(filename).gsub(/[\.\-]/, "_").upcase
end

def process_file(filename, out, outh, outc)
  var = var_name(out)
  size = File.size(filename)

  outh.write "extern const uint8_t #{var}[#{size}];\n"
  outc.write "#{@section}const uint8_t #{var}[#{size}] = {"

  File.new(filename).each_byte() do |b|
    outc.write b.to_s
    outc.write ", "
  end

  outc.write "};\n"

  return var, size
end

inp, out = *ARGV

outh = File.new(out + ".h", "w")
outc = File.new(out + ".c", "w")

outh.write "// Generated from content of #{inp}\n"
outh.write "#pragma once\n\n"
outh.write "#include <stdint.h>\n"
outh.write "#include <stddef.h>\n\n"

outc.write "// Generated from #{inp}\n\n"
outc.write "#include <stdint.h>\n"
outc.write "#include \"#{File.basename(out)}.h\"\n\n"

if File.directory?(inp)
  # XXX right now we handle only 1 level deep, maybe we should scan dirs recurvively?

  files = []
  for f in Dir.glob(inp + "/*")
    var, size = process_file(f, f, outh, outc)
    files << [var, size]
  end

  # all files in a directory also represented as an array
  var = var_name(out)
  outh.write "\nstruct blob_record {const void *data; const size_t size;};\n"
  outh.write "extern const struct blob_record #{var}[#{files.size}];\n"
  outc.write "\n#{@section}const struct blob_record #{var}[#{files.size}] = {"
  for f in files
    outc.write "{#{f[0]}, #{f[1]}}, "
  end
  outc.write "};\n"
else
  process_file(inp, out, outh, outc)
end

outh.close
outc.close
