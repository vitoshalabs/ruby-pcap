# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |gem|
  gem.name          = "ruby-pcap"
  gem.version       = "0.7.7"
  gem.authors       = [%q{Masaki Fukushima}, %q{Andrew Hobson}]
  gem.email         = ["mbarczak@gmail.com"]
  gem.description   = %q{Ruby interface to LBL Packet Capture library. This library also includes classes to access packet header fields.}
  gem.summary       = %q{Ruby interface to LBL Packet Capture library. This library also includes classes to access packet header fields.}
  gem.homepage      = "https://github.com/ickymettle/ruby-libpcap"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
end
