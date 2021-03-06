
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "rbs/version"

Gem::Specification.new do |spec|
  spec.name          = "rbs"
  spec.version       = RBS::VERSION
  spec.authors       = ["Soutaro Matsumoto"]
  spec.email         = ["matsumoto@soutaro.com"]

  spec.summary       = %q{Type signature for Ruby.}
  spec.description   = %q{RBS is the language for type signatures for Ruby and standard library definitions.}
  spec.homepage      = "https://github.com/ruby/rbs"
  spec.licenses      = ['BSD-2-Clause', 'Ruby']

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata["homepage_uri"] = spec.homepage
    spec.metadata["source_code_uri"] = "https://github.com/ruby/rbs.git"
    spec.metadata["changelog_uri"] = "https://github.com/ruby/rbs/blob/master/CHANGELOG.md"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.files << "lib/rbs/parser.rb"
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "racc", "~> 1.4.16"
  spec.add_development_dependency "rubocop"
  spec.add_development_dependency "rubocop-rubycw"
  spec.add_development_dependency "minitest-reporters", "~> 1.3.6"
  spec.add_development_dependency "json", "~> 2.3.0"
end
