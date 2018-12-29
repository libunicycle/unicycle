# SPDX-License-Identifier: MIT

class Bin2C
  def id
    :bin2c
  end

  def rule
    binpath = Shog::Path.make("scripts/bin2c.rb", :root => true).to_str
    {
      "command" => binpath + " $section $in $outdir",
      "description" => "Bin2C $in",
    }
  end

  def target(params)
    input = params[:input]
    outdir = params[:outdir] || input
    output = Shog::PathSet.new
    out = Shog::Path.make(outdir, :outoftree => true)
    output << out.with_suffix(".h")
    output << out.with_suffix(".c")
    variables = {
      :outdir => out.to_str,
    }
    if params[:section]
      variables[:section] = "--section " + params[:section]
    end
    { :rule => "bin2c", :input => input, :output => output, :variables => variables }
  end
end
