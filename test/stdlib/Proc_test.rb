require_relative "test_helper"

class ProcTest < StdlibTest
  target Proc
  # library "pathname", "set", "securerandom"     # Declare library signatures to load
  using hook.refinement

  def test_arity
    proc {}.arity
    proc { || }.arity
    proc { |a| }.arity
  end

  def test_binding
    proc {}.binding
  end

  def test_call
    proc { |a| a }.call 1
  end

  def test_index
    proc { |a| a }[1]
  end

  def test_curry
    b = proc { |x, y, z| x + y + z }
    b.curry
    b.curry(2)
  end

  def test_hash
    proc {}.hash
  end

  def test_initialize
    Proc.new { |a| a }
    Proc.new
  end

  def test_lambda?
    proc {}.lambda?
    lambda {}.lambda?
  end

  def test_parameters
    prc = lambda{|x, y=42, *other|}
    prc.parameters
  end

  def test_source_location
    proc {}.source_location
  end

  def test_to_proc
    proc {}.to_proc
  end

  def test_to_s
    proc {}.to_s
  end

  def test_inspect
    proc {}.inspect
  end
end
