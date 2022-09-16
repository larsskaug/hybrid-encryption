package controllers

import java.security.{KeyPairGenerator, SecureRandom, Security}
import scala.collection.JavaConverters._
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec
import org.bouncycastle.jce.spec.ElGamalPublicKeySpec
import org.bouncycastle.jce.interfaces.ElGamalPublicKey
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import scala.util.Random

class ElGamal(val keySize: Int, val msg: String) {
  // Inspired by https://github.com/norkator/Cryptography/blob/master/src/cryptography/ciphers/elgamal/Elgamal.java
  val bc = new BouncyCastleProvider()
  Security.addProvider(bc);

  def createKeyPair(random: SecureRandom, keySize: Int) = {
    val generator = KeyPairGenerator.getInstance("ELGamal", bc)
    generator.initialize(keySize, random)
    generator.generateKeyPair
  }


  /** Borrowed from https://literateprograms.org/miller-rabin_primality_test__scala_.html */
  def miller_rabin_pass(a: BigInt, n: BigInt): Boolean = {
    var d: BigInt = 0
    var s: BigInt = 0
    var a_to_power: BigInt = 0
    var i: Int = 0
    d = n - 1
    s = 0
    while (d % 2 == 0) {
      d >>= 1
      s += 1
    }
    a_to_power = a.modPow(d, n)
    if (a_to_power == 1) {
      return true
    }
    for (i <- 1 to s.intValue) {
      if (a_to_power == n - 1) {
        return true
      }
      a_to_power = (a_to_power * a_to_power) % n
    }
    return (a_to_power == n - 1)
  }

  def miller_rabin(n: BigInt): Boolean = {
    var k: Int = 20
    for (i: Int <- 1 to k) {
      var a: BigInt = 0
      var rand: scala.util.Random = new scala.util.Random()
      while (a == 0) {
        a = new BigInt(new java.math.BigInteger("" + (rand.nextDouble() * n.doubleValue).toInt))
      }
      if (!miller_rabin_pass(a, n)) {
        return false
      }
    }
    return true
  }

  // Helper function to make sure a is in range {1,2,3,...,p-2}
  def getRand(p: BigInt, keySize: Int): BigInt = {
    val b = BigInt(keySize, scala.util.Random)
    if (b > BigInt("0") && b < p - BigInt("2")) b
    else getRand(p, keySize)
  }

  val zero = BigInt("0")
  val one = BigInt("1")

  def squareAndMultiply(a: BigInt, k: BigInt, n: BigInt): BigInt = {
    k match {
      case `zero` => `one`
      case `one` => a % n
      case _ => {
        val t_ = squareAndMultiply(a, k/2, n)
        val t = t_.pow(2) % n
        if (k % 2 == 0) t
        else ((a % n) * t) % n
      }
    }
  }

  val random = new SecureRandom();

  val parameterGenerator = new org.bouncycastle.crypto.generators.ElGamalParametersGenerator()
  parameterGenerator.init(keySize,1,random)

  val params = parameterGenerator.generateParameters()

  // 1. Generate a large random prime p
  val p = params.getP

  // Generator (alpha)
  val g = params.getG

  // 2. Select a random integer a
  val a = getRand(p, keySize)

  // Compute alpha to the power of a mod p
  val alphaToPowerOfA = squareAndMultiply(g,a,p)

  def encrypt(): Map[String,BigInt] = {
    val m = BigInt(msg)
    // (c) select k
    val k_ = getRand(p, keySize).toString
    val k = new java.math.BigInteger(k_)
    // (d)
    val gamma = g.modPow(k,p)
    val delta = m * alphaToPowerOfA.modPow(k,p)

    Map("gamma" -> gamma, "delta" -> delta )
  }

  def decrypt(gamma: BigInt, delta: BigInt):BigInt = {
    // (a)
    val p_ = BigInt(p.toString())
    val decrypt_ = gamma.modPow(p_ - BigInt("1") - a, p_)

    // (b)
    val gamma_ = BigDecimal(gamma)
    decrypt_ * delta % p
  }



}

object Main {

  def main(args: Array[String]): Unit = {


    if (args.length != 2) {
      println("""Please provide two arguments: a key size in number of bits (e.g. 256) and a integer ("message") to encrypt""")
    }
    else {
      val elg = new ElGamal(args(0).toInt, args(1))
      println("Random number generated (which should be prime): " + elg.p)

      // p should be prime, but let's check
      elg.miller_rabin(elg.p) match {
        case true => println("p is indeed a prime")
        case _ => println("p does not seem to be a prime")
      }

      println("generator (alpha): " + elg.g)
      println("Value of a: " + elg.a)

      println("Alpha to the Power of a: " + elg.alphaToPowerOfA)

      println(s"Public key (p, alpha, a): (${elg.p}, ${elg.g}, ${elg.alphaToPowerOfA})")

      val encrypted = elg.encrypt()

      println(encrypted)

      println("decrypted: " + elg.decrypt(encrypted("gamma"), encrypted("delta")))

    }



  }
}