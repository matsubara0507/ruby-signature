module OpenSSL
  module TestUtils
    def assert_not_equal(exp, act)
      exp != act
    end

    def assert_not_nil(obj)
      not obj.nil?
    end

    def assert_raise(err)
      yield
      false
    rescue => e
      e == err
    end

    def assert_nothing_raised
      yield
      true
    rescue
      false
    end

    def assert_not_predicate(obj, predicate)
      obj.send(predicate.to_s) == false
    end

    def openssl?(major = nil, minor = nil, fix = nil, patch = 0)
      return false if OpenSSL::OPENSSL_VERSION.include?("LibreSSL")
      return true unless major
      OpenSSL::OPENSSL_VERSION_NUMBER >=
          major * 0x10000000 + minor * 0x100000 + fix * 0x1000 + patch * 0x10
    end

    def libressl?(major = nil, minor = nil, fix = nil)
      version = OpenSSL::OPENSSL_VERSION.scan(/LibreSSL (\d+)\.(\d+)\.(\d+).*/)[0]
      return false unless version
      !major || (version.map(&:to_i) <=> [major, minor, fix]) >= 0
    end
  end
end
