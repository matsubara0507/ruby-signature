require_relative "../test_helper"
require "openssl"

class OpenSSLASN1Test < StdlibTest
  target OpenSSL::ASN1
  library "openssl"

  using hook.refinement

  def test_decode_x509_certificate
    subj = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=TestCA")
    key = OpenSSL::PKey.read(File.read(File.join(__dir__, "fixtures", "pkey", "rsa1024.pem")))
    now = Time.at(Time.now.to_i) # suppress usec
    s = 0xdeadbeafdeadbeafdeadbeafdeadbeaf
    exts = [
      ["basicConstraints", "CA:TRUE,pathlen:1", true],
      ["keyUsage", "keyCertSign, cRLSign", true],
      ["subjectKeyIdentifier", "hash", false],
    ]
    dgst = OpenSSL::Digest::SHA1.new

    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = s
    cert.subject = subj
    cert.issuer = cert.subject
    cert.public_key = key
    cert.not_before = now
    cert.not_after = now + 3600
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    exts.each do |oid, value, critical|
      cert.add_extension(ef.create_extension(oid, value, critical))
    end
    cert.sign(key, dgst)

    asn1 = OpenSSL::ASN1.decode(cert)
    OpenSSL::ASN1::Sequence == asn1.class
    3 == asn1.value.size

    tbs_cert, sig_alg, sig_val = *asn1.value

    OpenSSL::ASN1::Sequence == tbs_cert.class
    8 == tbs_cert.value.size

    version = tbs_cert.value[0]
    :CONTEXT_SPECIFIC == version.tag_class
    0 == version.tag
    1 == version.value.size
    OpenSSL::ASN1::Integer == version.value[0].class
    2 == version.value[0].value

    serial = tbs_cert.value[1]
    OpenSSL::ASN1::Integer == serial.class
    0xdeadbeafdeadbeafdeadbeafdeadbeaf == serial.value

    sig = tbs_cert.value[2]
    OpenSSL::ASN1::Sequence == sig.class
    2 == sig.value.size
    OpenSSL::ASN1::ObjectId == sig.value[0].class
    "1.2.840.113549.1.1.5" == sig.value[0].oid
    OpenSSL::ASN1::Null == sig.value[1].class

    dn = tbs_cert.value[3] # issuer
    subj.hash == OpenSSL::X509::Name.new(dn).hash
    OpenSSL::ASN1::Sequence == dn.class
    3 == dn.value.size
    OpenSSL::ASN1::Set == dn.value[0].class
    OpenSSL::ASN1::Set == dn.value[1].class
    OpenSSL::ASN1::Set == dn.value[2].class
    1 == dn.value[0].value.size
    1 == dn.value[1].value.size
    1 == dn.value[2].value.size
    OpenSSL::ASN1::Sequence == dn.value[0].value[0].class
    OpenSSL::ASN1::Sequence == dn.value[1].value[0].class
    OpenSSL::ASN1::Sequence == dn.value[2].value[0].class
    2 == dn.value[0].value[0].value.size
    2 == dn.value[1].value[0].value.size
    2 == dn.value[2].value[0].value.size
    oid, value = *dn.value[0].value[0].value
    OpenSSL::ASN1::ObjectId == oid.class
    "0.9.2342.19200300.100.1.25" == oid.oid
    OpenSSL::ASN1::IA5String == value.class
    "org" == value.value
    oid, value = *dn.value[1].value[0].value
    OpenSSL::ASN1::ObjectId == oid.class
    "0.9.2342.19200300.100.1.25" == oid.oid
    OpenSSL::ASN1::IA5String == value.class
    "ruby-lang" == value.value
    oid, value = *dn.value[2].value[0].value
    OpenSSL::ASN1::ObjectId == oid.class
    "2.5.4.3" == oid.oid
    OpenSSL::ASN1::UTF8String == value.class
    "TestCA" == value.value

    validity = tbs_cert.value[4]
    OpenSSL::ASN1::Sequence == validity.class
    2 == validity.value.size
    OpenSSL::ASN1::UTCTime == validity.value[0].class
    now == validity.value[0].value
    OpenSSL::ASN1::UTCTime == validity.value[1].class
    now+3600 == validity.value[1].value

    dn = tbs_cert.value[5] # subject
    subj.hash == OpenSSL::X509::Name.new(dn).hash
    OpenSSL::ASN1::Sequence == dn.class
    3 == dn.value.size
    OpenSSL::ASN1::Set == dn.value[0].class
    OpenSSL::ASN1::Set == dn.value[1].class
    OpenSSL::ASN1::Set == dn.value[2].class
    1 == dn.value[0].value.size
    1 == dn.value[1].value.size
    1 == dn.value[2].value.size
    OpenSSL::ASN1::Sequence == dn.value[0].value[0].class
    OpenSSL::ASN1::Sequence == dn.value[1].value[0].class
    OpenSSL::ASN1::Sequence == dn.value[2].value[0].class
    2 == dn.value[0].value[0].value.size
    2 == dn.value[1].value[0].value.size
    2 == dn.value[2].value[0].value.size
    oid, value = *dn.value[0].value[0].value
    OpenSSL::ASN1::ObjectId == oid.class
    "0.9.2342.19200300.100.1.25" == oid.oid
    OpenSSL::ASN1::IA5String == value.class
    "org" == value.value
    oid, value = *dn.value[1].value[0].value
    OpenSSL::ASN1::ObjectId == oid.class
    "0.9.2342.19200300.100.1.25" == oid.oid
    OpenSSL::ASN1::IA5String == value.class
    "ruby-lang" == value.value
    oid, value = *dn.value[2].value[0].value
    OpenSSL::ASN1::ObjectId == oid.class
    "2.5.4.3" == oid.oid
    OpenSSL::ASN1::UTF8String == value.class
    "TestCA" == value.value

    pkey = tbs_cert.value[6]
    OpenSSL::ASN1::Sequence == pkey.class
    2 == pkey.value.size
    OpenSSL::ASN1::Sequence == pkey.value[0].class
    2 == pkey.value[0].value.size
    OpenSSL::ASN1::ObjectId == pkey.value[0].value[0].class
    "1.2.840.113549.1.1.1" == pkey.value[0].value[0].oid
    OpenSSL::ASN1::BitString == pkey.value[1].class
    0 == pkey.value[1].unused_bits
    spkey = OpenSSL::ASN1.decode(pkey.value[1].value)
    OpenSSL::ASN1::Sequence == spkey.class
    2 == spkey.value.size
    OpenSSL::ASN1::Integer == spkey.value[0].class
    cert.public_key.n == spkey.value[0].value
    OpenSSL::ASN1::Integer == spkey.value[1].class
    cert.public_key.e == spkey.value[1].value

    extensions = tbs_cert.value[7]
    :CONTEXT_SPECIFIC == extensions.tag_class
    3 == extensions.tag
    1 == extensions.value.size
    OpenSSL::ASN1::Sequence == extensions.value[0].class
    3 == extensions.value[0].value.size

    ext = extensions.value[0].value[0]  # basicConstraints
    OpenSSL::ASN1::Sequence == ext.class
    3 == ext.value.size
    OpenSSL::ASN1::ObjectId == ext.value[0].class
    "2.5.29.19" ==  ext.value[0].oid
    OpenSSL::ASN1::Boolean == ext.value[1].class
    true == ext.value[1].value
    OpenSSL::ASN1::OctetString == ext.value[2].class
    extv = OpenSSL::ASN1.decode(ext.value[2].value)
    OpenSSL::ASN1::Sequence == extv.class
    2 == extv.value.size
    OpenSSL::ASN1::Boolean == extv.value[0].class
    true == extv.value[0].value
    OpenSSL::ASN1::Integer == extv.value[1].class
    1 == extv.value[1].value

    ext = extensions.value[0].value[1]  # keyUsage
    OpenSSL::ASN1::Sequence == ext.class
    3 == ext.value.size
    OpenSSL::ASN1::ObjectId == ext.value[0].class
    "2.5.29.15" ==  ext.value[0].oid
    OpenSSL::ASN1::Boolean == ext.value[1].class
    true == ext.value[1].value
    OpenSSL::ASN1::OctetString == ext.value[2].class
    extv = OpenSSL::ASN1.decode(ext.value[2].value)
    OpenSSL::ASN1::BitString == extv.class
    str = +"\000"; str[0] = 0b00000110.chr
    str == extv.value

    ext = extensions.value[0].value[2]  # subjetKeyIdentifier
    OpenSSL::ASN1::Sequence == ext.class
    2 == ext.value.size
    OpenSSL::ASN1::ObjectId == ext.value[0].class
    "2.5.29.14" ==  ext.value[0].oid
    OpenSSL::ASN1::OctetString == ext.value[1].class
    extv = OpenSSL::ASN1.decode(ext.value[1].value)
    OpenSSL::ASN1::OctetString == extv.class
    sha1 = OpenSSL::Digest::SHA1.new
    sha1.update(pkey.value[1].value)
    sha1.digest == extv.value

    OpenSSL::ASN1::Sequence == sig_alg.class
    2 == sig_alg.value.size
    OpenSSL::ASN1::ObjectId == pkey.value[0].value[0].class
    "1.2.840.113549.1.1.1" == pkey.value[0].value[0].oid
    OpenSSL::ASN1::Null == pkey.value[0].value[1].class

    OpenSSL::ASN1::BitString == sig_val.class
    cululated_sig = key.sign(OpenSSL::Digest::SHA1.new, tbs_cert.to_der)
    cululated_sig == sig_val.value
  end

  def test_decode_all
    raw = B(%w{ 02 01 01 02 01 02 02 01 03 })
    ary = OpenSSL::ASN1.decode_all(raw)
    3 == ary.size
    ary.each_with_index do |asn1, i|
      i + 1 == asn1.value
    end
  end

  def test_object_id_register
    oid = "1.2.34.56789"
    OpenSSL::ASN1::ObjectId(oid).sn
    true == OpenSSL::ASN1::ObjectId.register(oid, "ossl-test-sn", "ossl-test-ln")
    obj = OpenSSL::ASN1::ObjectId(oid)
    oid == obj.oid
    "ossl-test-sn" == obj.sn
    "ossl-test-ln" == obj.ln
    obj = encode_decode_test B(%w{ 06 05 2A 22 83 BB 55 }), OpenSSL::ASN1::ObjectId("ossl-test-ln")
    "ossl-test-sn" == obj.value
  end

  def test_end_of_content
    encode_decode_test B(%w{ 00 00 }), OpenSSL::ASN1::EndOfContent.new
  end

  def test_boolean
    encode_decode_test B(%w{ 01 01 00 }), OpenSSL::ASN1::Boolean.new(false)
    encode_decode_test B(%w{ 01 01 FF }), OpenSSL::ASN1::Boolean.new(true)
    decode_test B(%w{ 01 01 01 }), OpenSSL::ASN1::Boolean.new(true)
  end

  def test_integer
    encode_decode_test B(%w{ 02 01 00 }), OpenSSL::ASN1::Integer.new(0)
    encode_decode_test B(%w{ 02 01 48 }), OpenSSL::ASN1::Integer.new(72)
    encode_decode_test B(%w{ 02 02 00 80 }), OpenSSL::ASN1::Integer.new(128)
    encode_decode_test B(%w{ 02 01 81 }), OpenSSL::ASN1::Integer.new(-127)
    encode_decode_test B(%w{ 02 01 80 }), OpenSSL::ASN1::Integer.new(-128)
    encode_decode_test B(%w{ 02 01 FF }), OpenSSL::ASN1::Integer.new(-1)
    encode_decode_test B(%w{ 02 09 01 00 00 00 00 00 00 00 00 }), OpenSSL::ASN1::Integer.new(2 ** 64)
    encode_decode_test B(%w{ 02 09 FF 00 00 00 00 00 00 00 00 }), OpenSSL::ASN1::Integer.new(-(2 ** 64))
    # FIXME: OpenSSL < 1.1.0 does not fail
    # assert_raise(OpenSSL::ASN1::ASN1Error) {
    #   OpenSSL::ASN1.decode(B(%w{ 02 02 00 7F }))
    # }
    # assert_raise(OpenSSL::ASN1::ASN1Error) {
    #   OpenSSL::ASN1.decode(B(%w{ 02 02 FF 80 }))
    # }
  end

  def test_enumerated
    encode_decode_test B(%w{ 0A 01 00 }), OpenSSL::ASN1::Enumerated.new(0)
    encode_decode_test B(%w{ 0A 01 48 }), OpenSSL::ASN1::Enumerated.new(72)
    encode_decode_test B(%w{ 0A 02 00 80 }), OpenSSL::ASN1::Enumerated.new(128)
    encode_decode_test B(%w{ 0A 09 01 00 00 00 00 00 00 00 00 }), OpenSSL::ASN1::Enumerated.new(2 ** 64)
  end

  def test_bitstring
    encode_decode_test B(%w{ 03 01 00 }), OpenSSL::ASN1::BitString.new(B(%w{}))
    encode_decode_test B(%w{ 03 02 00 01 }), OpenSSL::ASN1::BitString.new(B(%w{ 01 }))
    obj = OpenSSL::ASN1::BitString.new(B(%w{ F0 }))
    obj.unused_bits = 4
    encode_decode_test B(%w{ 03 02 04 F0 }), obj
    # OpenSSL < OpenSSL_1_0_1k and LibreSSL ignore the error
    # assert_raise(OpenSSL::ASN1::ASN1Error) {
    #   OpenSSL::ASN1.decode(B(%w{ 03 03 08 FF 00 }))
    # }
    # OpenSSL does not seem to prohibit this, though X.690 8.6.2.3 (15/08) does
    # assert_raise(OpenSSL::ASN1::ASN1Error) {
    #   OpenSSL::ASN1.decode(B(%w{ 03 01 04 }))
    # }
  end

  def test_string_basic
    test = -> (tag, klass) {
      encode_decode_test tag.chr + B(%w{ 00 }), klass.new(B(%w{}))
      encode_decode_test tag.chr + B(%w{ 02 00 01 }), klass.new(B(%w{ 00 01 }))
    }
    test.(4, OpenSSL::ASN1::OctetString)
    test.(12, OpenSSL::ASN1::UTF8String)
    test.(18, OpenSSL::ASN1::NumericString)
    test.(19, OpenSSL::ASN1::PrintableString)
    test.(20, OpenSSL::ASN1::T61String)
    test.(21, OpenSSL::ASN1::VideotexString)
    test.(22, OpenSSL::ASN1::IA5String)
    test.(25, OpenSSL::ASN1::GraphicString)
    test.(26, OpenSSL::ASN1::ISO64String)
    test.(27, OpenSSL::ASN1::GeneralString)
    test.(28, OpenSSL::ASN1::UniversalString)
    test.(30, OpenSSL::ASN1::BMPString)
  end

  def test_null
    encode_decode_test B(%w{ 05 00 }), OpenSSL::ASN1::Null.new(nil)
  end

  def test_object_identifier
    encode_decode_test B(%w{ 06 01 00 }), OpenSSL::ASN1::ObjectId.new("0.0".b)
    encode_decode_test B(%w{ 06 01 28 }), OpenSSL::ASN1::ObjectId.new("1.0".b)
    encode_decode_test B(%w{ 06 03 88 37 03 }), OpenSSL::ASN1::ObjectId.new("2.999.3".b)
    encode_decode_test B(%w{ 06 05 2A 22 83 BB 55 }), OpenSSL::ASN1::ObjectId.new("1.2.34.56789".b)
    obj = encode_decode_test B(%w{ 06 09 60 86 48 01 65 03 04 02 01 }), OpenSSL::ASN1::ObjectId.new("sha256")
    "2.16.840.1.101.3.4.2.1" == obj.oid
    "SHA256" == obj.sn
    "sha256" == obj.ln

    oid = (0...100).to_a.join(".").b
    obj = OpenSSL::ASN1::ObjectId.new(oid)
    oid == obj.oid

    aki = [
        OpenSSL::ASN1::ObjectId.new("authorityKeyIdentifier"),
        OpenSSL::ASN1::ObjectId.new("X509v3 Authority Key Identifier"),
        OpenSSL::ASN1::ObjectId.new("2.5.29.35")
    ]

    ski = [
        OpenSSL::ASN1::ObjectId.new("subjectKeyIdentifier"),
        OpenSSL::ASN1::ObjectId.new("X509v3 Subject Key Identifier"),
        OpenSSL::ASN1::ObjectId.new("2.5.29.14")
    ]

    aki.each do |a|
      aki.each do |b|
        a == b
      end

      ski.each do |b|
        a == b
      end
    end
  end

  def test_sequence
    encode_decode_test B(%w{ 30 00 }), OpenSSL::ASN1::Sequence.new([])
    encode_decode_test B(%w{ 30 07 05 00 30 00 04 01 00 }), OpenSSL::ASN1::Sequence.new([
                                                                                            OpenSSL::ASN1::Null.new(nil),
                                                                                            OpenSSL::ASN1::Sequence.new([]),
                                                                                            OpenSSL::ASN1::OctetString.new(B(%w{ 00 }))
                                                                                        ])

    expected = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::OctetString.new(B(%w{ 00 }))])
    expected.indefinite_length = true
    encode_decode_test B(%w{ 30 80 04 01 00 00 00 }), expected

    # OpenSSL::ASN1::EndOfContent can only be at the end
    obj = OpenSSL::ASN1::Sequence.new([
                                          OpenSSL::ASN1::EndOfContent.new,
                                          OpenSSL::ASN1::OctetString.new(B(%w{ 00 })),
                                          OpenSSL::ASN1::EndOfContent.new,
                                      ])
    obj.indefinite_length = true

    # The last EOC in value is ignored if indefinite length form is used
    expected = OpenSSL::ASN1::Sequence.new([
                                               OpenSSL::ASN1::OctetString.new(B(%w{ 00 })),
                                               OpenSSL::ASN1::EndOfContent.new
                                           ])
    expected.indefinite_length = true
    encode_test B(%w{ 30 80 04 01 00 00 00 }), expected
  end

  def test_set
    encode_decode_test B(%w{ 31 00 }), OpenSSL::ASN1::Set.new([])
    encode_decode_test B(%w{ 31 07 05 00 30 00 04 01 00 }), OpenSSL::ASN1::Set.new([
                                                                                       OpenSSL::ASN1::Null.new(nil),
                                                                                       OpenSSL::ASN1::Sequence.new([]),
                                                                                       OpenSSL::ASN1::OctetString.new(B(%w{ 00 }))
                                                                                   ])
    expected = OpenSSL::ASN1::Set.new([OpenSSL::ASN1::OctetString.new(B(%w{ 00 }))])
    expected.indefinite_length = true
    encode_decode_test B(%w{ 31 80 04 01 00 00 00 }), expected
  end

  def test_utctime
    encode_decode_test B(%w{ 17 0D }) + "160908234339Z".b,
                       OpenSSL::ASN1::UTCTime.new(Time.utc(2016, 9, 8, 23, 43, 39))
    # Seconds is omitted
    decode_test B(%w{ 17 0B }) + "1609082343Z".b,
                OpenSSL::ASN1::UTCTime.new(Time.utc(2016, 9, 8, 23, 43, 0))
    begin
      # possible range of UTCTime is 1969-2068 currently
      encode_decode_test B(%w{ 17 0D }) + "690908234339Z".b,
                         OpenSSL::ASN1::UTCTime.new(Time.utc(1969, 9, 8, 23, 43, 39))
    rescue OpenSSL::ASN1::ASN1Error
      pend "No negative time_t support?"
    end
    # not implemented
    # decode_test B(%w{ 17 11 }) + "500908234339+0930".b,
    #   OpenSSL::ASN1::UTCTime.new(Time.new(1950, 9, 8, 23, 43, 39, "+09:30"))
    # decode_test B(%w{ 17 0F }) + "5009082343-0930".b,
    #   OpenSSL::ASN1::UTCTime.new(Time.new(1950, 9, 8, 23, 43, 0, "-09:30"))
    # assert_raise(OpenSSL::ASN1::ASN1Error) {
    #   OpenSSL::ASN1.decode(B(%w{ 17 0C }) + "500908234339".b)
    # }
    # assert_raise(OpenSSL::ASN1::ASN1Error) {
    #   OpenSSL::ASN1.decode(B(%w{ 17 0D }) + "500908234339Y".b)
    # }
  end

  def test_generalizedtime
    encode_decode_test B(%w{ 18 0F }) + "20161208193429Z".b,
                       OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 34, 29))
    encode_decode_test B(%w{ 18 0F }) + "99990908234339Z".b,
                       OpenSSL::ASN1::GeneralizedTime.new(Time.utc(9999, 9, 8, 23, 43, 39))
    decode_test B(%w{ 18 0D }) + "201612081934Z".b,
                OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 34, 0))
    # not implemented
    # decode_test B(%w{ 18 13 }) + "20161208193439+0930".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.new(2016, 12, 8, 19, 34, 39, "+09:30"))
    # decode_test B(%w{ 18 11 }) + "201612081934-0930".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.new(2016, 12, 8, 19, 34, 0, "-09:30"))
    # decode_test B(%w{ 18 11 }) + "201612081934-09".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.new(2016, 12, 8, 19, 34, 0, "-09:00"))
    # decode_test B(%w{ 18 0D }) + "2016120819.5Z".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 30, 0))
    # decode_test B(%w{ 18 0D }) + "2016120819,5Z".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 30, 0))
    # decode_test B(%w{ 18 0F }) + "201612081934.5Z".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 34, 30))
    # decode_test B(%w{ 18 11 }) + "20161208193439.5Z".b,
    #   OpenSSL::ASN1::GeneralizedTime.new(Time.utc(2016, 12, 8, 19, 34, 39.5))
    # assert_raise(OpenSSL::ASN1::ASN1Error) {
    #   OpenSSL::ASN1.decode(B(%w{ 18 0D }) + "201612081934Y".b)
    # }
  end

  def test_basic_asn1data
    encode_test B(%w{ 00 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 0, :UNIVERSAL)
    encode_test B(%w{ 01 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 1, :UNIVERSAL)
    encode_decode_test B(%w{ 41 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 1, :APPLICATION)
    encode_decode_test B(%w{ 81 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 1, :CONTEXT_SPECIFIC)
    encode_decode_test B(%w{ C1 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 1, :PRIVATE)
    encode_decode_test B(%w{ 1F 20 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 32, :UNIVERSAL)
    encode_decode_test B(%w{ 1F C0 20 00 }), OpenSSL::ASN1::ASN1Data.new(B(%w{}), 8224, :UNIVERSAL)
    encode_decode_test B(%w{ 41 02 AB CD }), OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 1, :APPLICATION)
    encode_decode_test B(%w{ 41 81 80 } + %w{ AB CD } * 64), OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD } * 64), 1, :APPLICATION)
    encode_decode_test B(%w{ 41 82 01 00 } + %w{ AB CD } * 128), OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD } * 128), 1, :APPLICATION)
    encode_decode_test B(%w{ 61 00 }), OpenSSL::ASN1::ASN1Data.new([], 1, :APPLICATION)
    obj = OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 2, :PRIVATE)], 1, :APPLICATION)
    obj.indefinite_length = true
    encode_decode_test B(%w{ 61 80 C2 02 AB CD 00 00 }), obj
    obj = OpenSSL::ASN1::ASN1Data.new([
                                          OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 2, :PRIVATE),
                                          OpenSSL::ASN1::EndOfContent.new
                                      ], 1, :APPLICATION)
    obj.indefinite_length = true
    encode_test B(%w{ 61 80 C2 02 AB CD 00 00 }), obj
    obj = OpenSSL::ASN1::ASN1Data.new(B(%w{ AB CD }), 1, :UNIVERSAL)
  end

  def test_basic_primitive
    encode_test B(%w{ 00 00 }), OpenSSL::ASN1::Primitive.new(B(%w{}), 0)
    encode_test B(%w{ 01 00 }), OpenSSL::ASN1::Primitive.new(B(%w{}), 1, nil, :UNIVERSAL)
    encode_test B(%w{ 81 00 }), OpenSSL::ASN1::Primitive.new(B(%w{}), 1, nil, :CONTEXT_SPECIFIC)
    encode_test B(%w{ 01 02 AB CD }), OpenSSL::ASN1::Primitive.new(B(%w{ AB CD }), 1)

    prim = OpenSSL::ASN1::Integer.new(50)
    false == prim.indefinite_length
  end

  def test_basic_constructed
    octet_string = OpenSSL::ASN1::OctetString.new(B(%w{ AB CD }))
    encode_test B(%w{ 20 00 }), OpenSSL::ASN1::Constructive.new([], 0)
    encode_test B(%w{ 21 00 }), OpenSSL::ASN1::Constructive.new([], 1, nil, :UNIVERSAL)
    encode_test B(%w{ A1 00 }), OpenSSL::ASN1::Constructive.new([], 1, nil, :CONTEXT_SPECIFIC)
    encode_test B(%w{ 21 04 04 02 AB CD }), OpenSSL::ASN1::Constructive.new([octet_string], 1)
    obj = OpenSSL::ASN1::Constructive.new([octet_string], 1)
    obj.indefinite_length = true
    encode_decode_test B(%w{ 21 80 04 02 AB CD 00 00 }), obj
    obj = OpenSSL::ASN1::Constructive.new([octet_string, OpenSSL::ASN1::EndOfContent.new], 1)
    obj.indefinite_length = true
    encode_test B(%w{ 21 80 04 02 AB CD 00 00 }), obj
  end

  def test_prim_explicit_tagging
    oct_str = OpenSSL::ASN1::OctetString.new("a", 0, :EXPLICIT)
    encode_test B(%w{ A0 03 04 01 61 }), oct_str
    oct_str2 = OpenSSL::ASN1::OctetString.new("a", 1, :EXPLICIT, :APPLICATION)
    encode_test B(%w{ 61 03 04 01 61 }), oct_str2

    decoded = OpenSSL::ASN1.decode(oct_str2.to_der)
    :APPLICATION == decoded.tag_class
    1 == decoded.tag
    1 == decoded.value.size
    inner = decoded.value[0]
    OpenSSL::ASN1::OctetString == inner.class
    B(%w{ 61 }) == inner.value
  end

  def test_prim_implicit_tagging
    int = OpenSSL::ASN1::Integer.new(1, 0, :IMPLICIT)
    encode_test B(%w{ 80 01 01 }), int
    int2 = OpenSSL::ASN1::Integer.new(1, 1, :IMPLICIT, :APPLICATION)
    encode_test B(%w{ 41 01 01 }), int2
    decoded = OpenSSL::ASN1.decode(int2.to_der)
    :APPLICATION == decoded.tag_class
    1 == decoded.tag
    B(%w{ 01 }) == decoded.value

    # Special behavior: Encoding universal types with non-default 'tag'
    # attribute and nil tagging method.
    int3 = OpenSSL::ASN1::Integer.new(1, 1)
    encode_test B(%w{ 01 01 01 }), int3
  end

  def test_cons_explicit_tagging
    content = [ OpenSSL::ASN1::PrintableString.new('abc') ]
    seq = OpenSSL::ASN1::Sequence.new(content, 2, :EXPLICIT)
    encode_test B(%w{ A2 07 30 05 13 03 61 62 63 }), seq
    seq2 = OpenSSL::ASN1::Sequence.new(content, 3, :EXPLICIT, :APPLICATION)
    encode_test B(%w{ 63 07 30 05 13 03 61 62 63 }), seq2

    content3 = [ OpenSSL::ASN1::PrintableString.new('abc'),
                 OpenSSL::ASN1::EndOfContent.new() ]
    seq3 = OpenSSL::ASN1::Sequence.new(content3, 2, :EXPLICIT)
    seq3.indefinite_length = true
    encode_test B(%w{ A2 80 30 80 13 03 61 62 63 00 00 00 00 }), seq3
  end

  def test_cons_implicit_tagging
    content = [ OpenSSL::ASN1::Null.new(nil) ]
    seq = OpenSSL::ASN1::Sequence.new(content, 1, :IMPLICIT)
    encode_test B(%w{ A1 02 05 00 }), seq
    seq2 = OpenSSL::ASN1::Sequence.new(content, 1, :IMPLICIT, :APPLICATION)
    encode_test B(%w{ 61 02 05 00 }), seq2

    content3 = [ OpenSSL::ASN1::Null.new(nil),
                 OpenSSL::ASN1::EndOfContent.new() ]
    seq3 = OpenSSL::ASN1::Sequence.new(content3, 1, :IMPLICIT)
    seq3.indefinite_length = true
    encode_test B(%w{ A1 80 05 00 00 00 }), seq3

    # Special behavior: Encoding universal types with non-default 'tag'
    # attribute and nil tagging method.
    seq4 = OpenSSL::ASN1::Sequence.new([], 1)
    encode_test B(%w{ 21 00 }), seq4
  end

  def test_octet_string_constructed_tagging
    octets = [ OpenSSL::ASN1::OctetString.new('aaa') ]
    cons = OpenSSL::ASN1::Constructive.new(octets, 0, :IMPLICIT)
    encode_test B(%w{ A0 05 04 03 61 61 61 }), cons

    octets = [ OpenSSL::ASN1::OctetString.new('aaa'),
               OpenSSL::ASN1::EndOfContent.new() ]
    cons = OpenSSL::ASN1::Constructive.new(octets, 0, :IMPLICIT)
    cons.indefinite_length = true
    encode_test B(%w{ A0 80 04 03 61 61 61 00 00 }), cons
  end

  def test_recursive_octet_string_indefinite_length
    octets_sub1 = [ OpenSSL::ASN1::OctetString.new("\x01"),
                    OpenSSL::ASN1::EndOfContent.new() ]
    octets_sub2 = [ OpenSSL::ASN1::OctetString.new("\x02"),
                    OpenSSL::ASN1::EndOfContent.new() ]
    container1 = OpenSSL::ASN1::Constructive.new(octets_sub1, OpenSSL::ASN1::OCTET_STRING, nil, :UNIVERSAL)
    container1.indefinite_length = true
    container2 = OpenSSL::ASN1::Constructive.new(octets_sub2, OpenSSL::ASN1::OCTET_STRING, nil, :UNIVERSAL)
    container2.indefinite_length = true
    octets3 = OpenSSL::ASN1::OctetString.new("\x03")

    octets = [ container1, container2, octets3,
               OpenSSL::ASN1::EndOfContent.new() ]
    cons = OpenSSL::ASN1::Constructive.new(octets, OpenSSL::ASN1::OCTET_STRING, nil, :UNIVERSAL)
    cons.indefinite_length = true
    raw = B(%w{ 24 80 24 80 04 01 01 00 00 24 80 04 01 02 00 00 04 01 03 00 00 })
    raw == cons.to_der
    raw == OpenSSL::ASN1.decode(raw).to_der
  end

  def test_recursive_octet_string_parse
    raw = B(%w{ 24 80 24 80 04 01 01 00 00 24 80 04 01 02 00 00 04 01 03 00 00 })
    asn1 = OpenSSL::ASN1.decode(raw)
    OpenSSL::ASN1::Constructive == asn1.class
    assert_universal(OpenSSL::ASN1::OCTET_STRING, asn1)
    true == asn1.indefinite_length
    3 == asn1.value.size
    nested1 = asn1.value[0]
    OpenSSL::ASN1::Constructive == nested1.class
    assert_universal(OpenSSL::ASN1::OCTET_STRING, nested1)
    true == nested1.indefinite_length
    1 == nested1.value.size
    oct1 = nested1.value[0]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct1)
    false == oct1.indefinite_length
    nested2 = asn1.value[1]
    OpenSSL::ASN1::Constructive == nested2.class
    assert_universal(OpenSSL::ASN1::OCTET_STRING, nested2)
    true == nested2.indefinite_length
    1 == nested2.value.size
    oct2 = nested2.value[0]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct2)
    false == oct2.indefinite_length
    oct3 = asn1.value[2]
    assert_universal(OpenSSL::ASN1::OCTET_STRING, oct3)
    false == oct3.indefinite_length
  end

  def test_decode_constructed_overread
    test = %w{ 31 06 31 02 30 02 05 00 }
    #                          ^ <- invalid
    raw = [test.join].pack("H*")
    ret = []
    begin
      OpenSSL::ASN1.traverse(raw) { |x| ret << x }
    rescue OpenSSL::ASN1::ASN1Error
      # nop
    end
    2 == ret.size
    17 == ret[0][6]
    17 == ret[1][6]

    test = %w{ 31 80 30 03 00 00 }
    #                    ^ <- invalid
    raw = [test.join].pack("H*")
    ret = []
    begin
      OpenSSL::ASN1.traverse(raw) { |depth, offset, header_len, length, constructed, tag_class, tag| ret << [depth, offset, header_len, length, constructed, tag_class, tag] }
    rescue OpenSSL::ASN1::ASN1Error
      # nop
    end
    1 == ret.size
    17 == ret[0][6]
  end

  def test_constructive_each
    data = [OpenSSL::ASN1::Integer.new(0), OpenSSL::ASN1::Integer.new(1)]
    seq = OpenSSL::ASN1::Sequence.new data

    data == seq.entries
  end

  # Very time consuming test.
  # def test_gc_stress
  #   assert_ruby_status(['--disable-gems', '-eGC.stress=true', '-erequire "openssl.so"'])
  # end

  private

  def B(ary)
    [ary.join].pack("H*")
  end

  def assert_asn1_equal(a, b)
    a.class == b.class
    a.tag == b.tag
    a.tag_class == b.tag_class
    a.indefinite_length == b.indefinite_length
    a.unused_bits == b.unused_bits if a.respond_to?(:unused_bits)
    case a.value
    when Array
      a.value.each_with_index { |ai, i|
        assert_asn1_equal ai, b.value[i]
      }
    else
      if OpenSSL::ASN1::ObjectId === a
        a.oid == b.oid
      else
        a.value == b.value
      end
    end
    a.to_der == b.to_der
  end

  def encode_test(der, obj)
    der == obj.to_der
  end

  def decode_test(der, obj)
    decoded = OpenSSL::ASN1.decode(der)
    assert_asn1_equal obj, decoded
    decoded
  end

  def encode_decode_test(der, obj)
    encode_test(der, obj)
    decode_test(der, obj)
  end

  def assert_universal(tag, asn1)
    tag == asn1.tag
    if asn1.respond_to?(:tagging)
      assert_nil(asn1.tagging)
    end
    :UNIVERSAL == asn1.tag_class
  end
end
