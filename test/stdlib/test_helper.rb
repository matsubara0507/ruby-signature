require "rbs"
require "rbs/test"
require "minitest/autorun"

require "minitest/reporters"
Minitest::Reporters.use!

class ToInt
  def initialize(value = 3)
    @value = value
  end

  def to_int
    @value
  end
end

class ToStr
  def initialize(value = "")
    @value = value
  end

  def to_str
    @value
  end
end

class ToS
  def initialize(value = "")
    @value = value
  end

  def to_s
    @value
  end
end

class ToArray
  def initialize(*args)
    @args = args
  end

  def to_ary
    @args
  end
end

class ToPath
  def initialize(value = "")
    @value = value
  end

  def to_path
    @value
  end
end

class ToJson
end

class JsonWrite
  def write(_str)
  end
end

class JsonToWritableIO
  def to_io
    JsonWrite.new
  end
end

class JsonRead
  def read
    "42"
  end
end

class JsonToReadableIO
  def to_io
    JsonRead.new
  end
end

class Enum
  def initialize(*args)
    @args = args
  end

  include Enumerable

  def each(&block)
    @args.each(&block)
  end
end

class ArefFromStringToString
  def [](str)
    "!"
  end
end

class StdlibTest < Minitest::Test

  DEFAULT_LOGGER = Logger.new(STDERR)
  DEFAULT_LOGGER.level = ENV["RBS_TEST_LOGLEVEL"] || "info"

  loader = RBS::EnvironmentLoader.new
  DEFAULT_ENV = RBS::Environment.new
  loader.load(env: DEFAULT_ENV)

  def self.target(klass)
    @target = klass
  end

  def self.env
    @env || DEFAULT_ENV
  end

  def self.library(*libs)
    loader = RBS::EnvironmentLoader.new
    libs.each do |lib|
      loader.add library: lib
    end

    @env = RBS::Environment.new
    loader.load(env: @env)
  end

  def self.hook
    @hook ||= RBS::Test::Hook.new(env, @target, logger: DEFAULT_LOGGER).verify_all
  end

  def hook
    self.class.hook
  end

  def setup
    super
    self.hook.errors.clear
    @assert = true
  end

  def teardown
    super
    assert_empty self.hook.errors.map {|x| RBS::Test::Errors.to_string(x) }
  end
end
