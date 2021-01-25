require_relative "../test_helper"
require "openssl"

class OpenSSLBNTest < StdlibTest
  target OpenSSL::BN
  library "openssl"

  using hook.refinement

  def setup
    super
    @e1 = OpenSSL::BN.new(999.to_s(16), 16) # OpenSSL::BN.new(str, 16) must be most stable
    @e2 = OpenSSL::BN.new("-" + 999.to_s(16), 16)
    @e3 = OpenSSL::BN.new((2**107-1).to_s(16), 16)
    @e4 = OpenSSL::BN.new("-" + (2**107-1).to_s(16), 16)
  end

  def test_new
    OpenSSL::BN.new("999")
    OpenSSL::BN.new("999", 10)
    OpenSSL::BN.new("\x03\xE7", 2)
    OpenSSL::BN.new("\x00\x00\x00\x02\x03\xE7", 0)
    OpenSSL::BN.new("-999")
    OpenSSL::BN.new("-999", 10)
    OpenSSL::BN.new("\x00\x00\x00\x02\x83\xE7", 0)
    OpenSSL::BN.new((2**107-1).to_s)
    OpenSSL::BN.new((2**107-1).to_s, 10)
    OpenSSL::BN.new("\a\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 2)
    OpenSSL::BN.new("\x00\x00\x00\x0E\a\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 0)
    OpenSSL::BN.new("-" + (2**107-1).to_s)
    OpenSSL::BN.new("-" + (2**107-1).to_s, 10)
    OpenSSL::BN.new("\x00\x00\x00\x0E\x87\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 0)

    e1copy = OpenSSL::BN.new(@e1)
    e1copy.clear_bit!(0) #=> 998
  end

  def test_to_str
    @e1.to_s(10)
    @e2.to_s(10)
    @e3.to_s(10)
    @e4.to_s(10)
    @e1.to_s

    @e1.to_s(16)
    @e2.to_s(16)
    @e3.to_s(16)
    @e4.to_s(16)

    @e1.to_s(2)
    @e2.to_s(2)
    @e3.to_s(2)
    @e4.to_s(2)

    @e1.to_s(0)
    @e2.to_s(0)
    @e3.to_s(0)
    @e4.to_s(0)
  end

  def test_to_int
    @e1.to_i
    @e2.to_i
    @e3.to_i
    @e4.to_i

    @e1.to_int
  end

  def test_coerce
    @e2.coerce("")
    @e2.coerce(1000)
  end

  def test_zero_p
    0.to_bn.zero?
    1.to_bn.zero?
  end

  def test_one_p
    1.to_bn.one?
    2.to_bn.one?
  end

  def test_odd_p
    1.to_bn.odd?
    2.to_bn.odd?
  end

  def test_negative_p
    0.to_bn.negative?
    @e1.negative?
    @e2.negative?
  end

  def test_sqr
    1.to_bn.sqr
    10.to_bn.sqr
  end

  def test_four_ops
    1.to_bn + 2
    1.to_bn + -2
    1.to_bn - 2
    1.to_bn - -2
    1.to_bn * 2
    1.to_bn * -2
    1.to_bn / 2
    2.to_bn / 1
  end

  def test_unary_plus_minus
    +@e1
    +@e2
    -@e1
    -@e2
  end

  def test_mod
    1.to_bn % 2
    2.to_bn % 1
    -2.to_bn % 7
  end

  def test_exp
    1.to_bn ** 5
    2.to_bn ** 5
  end

  def test_gcd
    7.to_bn.gcd(5)
    24.to_bn.gcd(16)
  end

  def test_mod_sqr
    3.to_bn.mod_sqr(5)
    59.to_bn.mod_sqr(59)
  end

  def test_mod_inverse
    3.to_bn.mod_inverse(5)
  end

  def test_mod_add
    3.to_bn.mod_add(5, 7)
    3.to_bn.mod_add(5, 3)
    3.to_bn.mod_add(-5, 7)
  end

  def test_mod_sub
    11.to_bn.mod_sub(3, 7)
    11.to_bn.mod_sub(3, 3)
    3.to_bn.mod_sub(5, 7)
  end

  def test_mod_mul
    2.to_bn.mod_mul(4, 7)
    2.to_bn.mod_mul(-1, 7)
  end

  def test_mod_exp
    3.to_bn.mod_exp(2, 8)
    2.to_bn.mod_exp(5, 7)
  end

  def test_bit_operations
    e = 0b10010010.to_bn
    e.set_bit!(0)
    e.set_bit!(1)
    e.set_bit!(9)

    e = 0b10010010.to_bn
    e.clear_bit!(0)
    e.clear_bit!(1)

    e = 0b10010010.to_bn
    e.mask_bits!(8)
    e.mask_bits!(3)

    e = 0b10010010.to_bn
    e.bit_set?(0)
    e.bit_set?(1)
    e.bit_set?(1000)

    e = 0b10010010.to_bn
    e << 2
    e.lshift!(2)

    e = 0b10010010.to_bn
    e >> 2
    e.rshift!(2)
  end

  def test_random
    OpenSSL::BN.rand(8)
    OpenSSL::BN.rand(8, -1)
    OpenSSL::BN.rand(8, 1)
    OpenSSL::BN.rand(8, 1, true)
    OpenSSL::BN.rand_range(256)
  end

  def test_prime
    p1 = OpenSSL::BN.generate_prime(32)
    p2 = OpenSSL::BN.generate_prime(32, true)
    p3 = OpenSSL::BN.generate_prime(32, false, 4)
    p4 = OpenSSL::BN.generate_prime(32, false, 4, 3)

    p1.prime?
    p2.prime?
    p3.prime?
    p4.prime?
    @e3.prime?
    @e3.prime_fasttest?
  end

  def test_num_bits_bytes
    @e1.num_bits
    @e1.num_bytes
    @e3.num_bits
    @e3.num_bytes
    0.to_bn.num_bits
    0.to_bn.num_bytes
    -256.to_bn.num_bits
    -256.to_bn.num_bytes
  end

  def test_comparison
    # @e1 == nil
    @e1 == -999
    @e1 == 999
    @e1 == 999.to_bn
    # @e1.eql?(nil)
    @e1.eql?(999)
    @e1.eql?(999.to_bn)
    999.to_bn.hash
    @e1.cmp(999)
    @e1.cmp(-999)
    @e1.ucmp(999)
    @e1.ucmp(-999)
  end
end
