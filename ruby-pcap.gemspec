# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |gem|
  gem.name          = "ruby-pcap"
  gem.version       = "0.8.1"
  gem.authors       = [%q{Masaki Fukushima}, %q{Andrew Hobson}, %q{Marcus Barczak}, %q{Vitosha Labs Open Source team}]
  gem.email         = ["opensource@vitosha-labs.bg"]
  gem.description   = %q{Ruby interface to LBL Packet Capture library. This library also includes classes to access packet header fields.}
  gem.summary       = %q{Ruby interface to LBL Packet Capture library.}
  gem.homepage      = "https://github.com/vitoshalabs/ruby-pcap"
  gem.license       = "GPL-2.0"

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.extensions << "ext/pcap/extconf.rb"

  gem.add_development_dependency "rake-compiler"
end
