# SPDX-License-Identifier: MIT

# Geenrate config.h from .config file
class GenConfig
  def id
    :genconfig
  end

  def rule
    @binpath = Shog::Path.make("scripts/gen_config_h.rb", :root => true).to_str
    {
      "command" => @binpath + " < $in > $out",
      "description" => "Generate config.h",
    }
  end

  def target(params)
    input = params[:input]
    output = params[:output]
    { :rule => "genconfig", :input => [input], :implicit_input => [@binpath], :output => [output] }
  end
end
