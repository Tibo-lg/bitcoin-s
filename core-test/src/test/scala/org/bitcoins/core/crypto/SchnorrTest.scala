package org.bitcoins.core.crypto

import org.bitcoin.NativeSecp256k1
import org.bitcoins.core.util.{CryptoUtil, NumberUtil}
import org.bitcoins.testkit.core.gen.{CryptoGenerators, NumberGenerator}
import org.bitcoins.testkit.util.BitcoinSUnitTest
import scodec.bits.ByteVector

class SchnorrTest extends BitcoinSUnitTest {
  implicit override val generatorDrivenConfig: PropertyCheckConfiguration =
    generatorDrivenConfigNewCode


  behavior of "NativeSecp256k1"

  it must "return the same pubkey" in {

    val pubkey = ECPublicKey.fromHex("02545471a397f40591cf72ce21b93c6b0515897540bb6ad1d3eba165769dcde563")
    val privkey = ECPrivateKey.fromHex("ded9a76a0a77399e1c2676324118a0386004633f16245ad30d172b15c1f9e2d3")
    val nonce = SchnorrNonce.fromBytes(org.bitcoins.core.util.BitcoinSUtil.decodeHex("be3cc8de25c50e25f69e2f88d151e3f63e99c3a44fed2bdd2e3ee70fe141c5c3"))
    val rPoint = ECPublicKey.fromHex("03447b31127de0b6313f6ee96618920a99cca5a0203cb26845fb5c142543741964")
    val data = org.bitcoins.core.util.BitcoinSUtil.decodeHex("0f92be0c4b13ce9b1adcb8b77ea1e7f272ae38fe698d5e9000e1122ce30378c0")
    val signerPrivKey = ECPrivateKey.fromHex("c2172cb3d358870c7b1bb1420a9364ffc66e2ec2c65b973554b66ec45e3d69dc")
    val signerPubKey = signerPrivKey.publicKey

    val sigWithNonce = NativeSecp256k1.schnorrSignWithNonce(data.toArray, privkey.bytes.toArray, nonce.bytes.toArray)
    val committedKey = NativeSecp256k1.computeSchnorrPubKey(data.toArray, rPoint.bytes.toArray, pubkey.bytes.toArray)
    val tweakKey = NativeSecp256k1.privKeyTweakAdd(signerPrivKey.bytes.toArray, sigWithNonce.slice(32, 64))
    val tweakPubkey = signerPubKey.add(ECPublicKey.fromBytes(ByteVector.apply(committedKey)))

    val privTweakKey = ECPrivateKey.fromBytes(ByteVector.apply(tweakKey))

    println(privTweakKey.publicKey.toString())
    println(tweakPubkey.toString())

    assert(tweakPubkey.equals(privTweakKey.publicKey))
  }

  it must "act like a normal schnorrSign if the normal nonce is specified" in {
    forAll(CryptoGenerators.nonZeroPrivKey, NumberGenerator.bytevector(32)) {
      case (privKey, message) =>
        // First lets manually generate the bip-schnorr nonce
        val nonce = SchnorrNonce.fromBipSchnorr(privKey, message)

        assert(nonce.bytes.toArray.exists(_ != 0.toByte))

        // Then we will sign with that nonce
        val sigWithNonce =
          NativeSecp256k1.schnorrSignWithNonce(message.toArray,
                                               privKey.bytes.toArray,
                                               nonce.bytes.toArray)

        // Make sure that NativeSecp256k1 doesn't deviate from Schnorr
        assert(
          SchnorrDigitalSignature(ByteVector(sigWithNonce)) ==
            Schnorr.signWithNonce(message, privKey, nonce)
        )

        // Then we will sign with no nonce specified
        val sig =
          NativeSecp256k1.schnorrSign(message.toArray, privKey.bytes.toArray)

        // Make sure that NativeSecp256k1 doesn't deviate from Schnorr
        assert(
          SchnorrDigitalSignature(ByteVector(sig)) ==
            Schnorr.sign(message, privKey)
        )

        // Finally, both signatures should be the same since we specified the bip-schnorr nonce
        assert(ByteVector(sigWithNonce) == ByteVector(sig))
    }
  }

  it must "correctly compute a Schnorr public key given an R value" in {
    forAll(CryptoGenerators.nonZeroPrivKey, NumberGenerator.bytevector(32)) {
      case (privKey, message) =>
        val publicKey: ECPublicKey = privKey.publicKey
        val messageArr: Array[Byte] = message.toArray

        // We manually compute the bip-schnorr nonce in order to compute R
        val nonce = SchnorrNonce.fromBipSchnorr(privKey, message)

        assert(nonce.bytes.toArray.exists(_ != 0.toByte))

        // R is the bip-schnorr nonce's publicKey
        val rBytes = nonce.publicKey.bytes

        // Sign message with privKey and bip-schnorr nonce
        val sig: Array[Byte] =
          NativeSecp256k1.schnorrSign(messageArr, privKey.bytes.toArray)

        // The first 32 bytes are the x-coordinate of R, the last 32 are the signature
        val (rKey, s) = sig.splitAt(32)

        // Assert our R value was the one used by comparing x-coordinates
        assert(rBytes.tail == ByteVector(rKey))

        // Compute the public key associated with s from public information
        // (s*G = R + m*P)
        val sPub: Array[Byte] =
          NativeSecp256k1.computeSchnorrPubKey(messageArr,
                                               rBytes.toArray,
                                               publicKey.bytes.toArray)
        val sPubKey: ECPublicKey = ECPublicKey.fromBytes(ByteVector(sPub))

        // Make sure that NativeSecp256k1 doesn't deviate from Schnorr
        assert(
          sPubKey == Schnorr.computePubKey(message, nonce.publicKey, publicKey))

        // Compute the public key associated with s from s itself (private info)
        val realSPriv = ECPrivateKey.fromBytes(ByteVector(s))
        val realSPub = realSPriv.publicKey

        // Assert that both ways of computing s*G are equal
        assert(sPubKey == realSPub)
    }
  }

  /* Schnorr signatures have the property that if two messages are signed with the same key
   * and nonce, then they are leaked:
   *
   * sig1 = nonce + message1*privKey
   * sig2 = nonce + message2*privKey
   *
   * => sig1 - sig2 = (message1 - message2)*privKey
   * => privKey = (sig1 - sig2) * inverse(message1 - message2)
   */
  it should "leak keys if two messages are signed" in {
    // The order of the secp256k1 curve (and thus the modulus of the field elements)
    val N = BigInt(CryptoParams.params.getN)

    /** Returns num % M as a positive integer */
    def modM(num: BigInt): BigInt = {
      if (num < 0) {
        (num % N) + N
      } else {
        num % N
      }
    }

    /** Computes the inverse (mod M) of the input using the Euclidean Algorithm (log time)
      * Cribbed from [[https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/]]
      */
    def modInverse(aInit: BigInt): BigInt = {
      var a = modM(aInit)
      var m = N
      var m0 = m
      var y = BigInt(0)
      var x = BigInt(1)

      if (m == 1)
        return 0

      while (a > 1) {
        // q is quotient
        val q = a / m

        var t = m

        // m is remainder now, process
        // same as Euclid's algo
        m = a % m
        a = t
        t = y

        // Update x and y
        y = x - q * y
        x = t
      }

      if (x < 0) {
        x += m0
      }

      modM(x)
    }

    forAll(CryptoGenerators.nonZeroPrivKey,
           CryptoGenerators.schnorrNonce,
           NumberGenerator.bytevector(32),
           NumberGenerator.bytevector(32)) {
      case (privKey, nonce, message1, message2) =>
        // This will only work if we sign two different messages
        assert(message1 != message2)

        // Sign both messages using the same privKey and nonce
        val sig1 = Schnorr.signWithNonce(message1, privKey, nonce)
        val sig2 = Schnorr.signWithNonce(message2, privKey, nonce)

        // s1 = nonce + e1*privKey
        val s1 = NumberUtil.toUnsignedInt(sig1.s)
        // s2 = nonce + e2*privKey
        val s2 = NumberUtil.toUnsignedInt(sig2.s)

        // When signing a message you actually sign SHA256(Rx || pubKey || message)
        val e1Bytes =
          CryptoUtil
            .sha256(sig1.rx ++ privKey.publicKey.bytes ++ message1)
            .bytes
        val e2Bytes =
          CryptoUtil
            .sha256(sig2.rx ++ privKey.publicKey.bytes ++ message2)
            .bytes

        val e1 = NumberUtil.toUnsignedInt(e1Bytes)
        val e2 = NumberUtil.toUnsignedInt(e2Bytes)

        // This tests that modInverse is working
        assert(modM(modInverse(e1 - e2) * modM(e1 - e2)) == BigInt(1))

        // Note that all of s1, s2, e1, and e2 are public information:
        // s1 - s2 = nonce + e1*privKey - (nonce + e2*privKey) = privKey*(e1-e2)
        // => privKey = (s1 - s2) * modInverse(e1 - e2)
        val privNum = modM(modM(s1 - s2) * modInverse(e1 - e2))

        // Assert that we've correctly recovered the private key form public info
        assert(privNum == NumberUtil.toUnsignedInt(privKey.bytes))
    }
  }
}
