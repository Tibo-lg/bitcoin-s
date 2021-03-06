package org.bitcoins.testkit.core.gen

import org.bitcoins.core.currency.{
  Bitcoins,
  CurrencyUnit,
  CurrencyUnits,
  Satoshis
}
import org.bitcoins.core.protocol.ln.currency._
import org.scalacheck.Gen
import org.bitcoins.core.wallet.fee.FeeUnit
import org.bitcoins.core.wallet.fee.SatoshisPerByte
import org.bitcoins.core.wallet.fee.SatoshisPerKiloByte
import org.bitcoins.core.wallet.fee.SatoshisPerVirtualByte

trait CurrencyUnitGenerator {

  def satsPerByte: Gen[SatoshisPerByte] = {
    for {
      curr <- positiveRealistic
    } yield SatoshisPerByte(curr)
  }

  def satsPerKiloByte: Gen[SatoshisPerKiloByte] = {
    for {
      curr <- positiveRealistic
    } yield SatoshisPerKiloByte(curr)
  }

  def satsPerVirtualByte: Gen[SatoshisPerVirtualByte] = {
    for {
      curr <- positiveRealistic
    } yield SatoshisPerVirtualByte(curr)
  }

  def feeUnit: Gen[FeeUnit] =
    Gen.oneOf(satsPerByte, satsPerKiloByte, satsPerVirtualByte)

  /** Generates a FeeUnit based on the maxFee allowed for a transaction */
  def feeUnit(maxFee: Long): Gen[FeeUnit] = {
    Gen.choose(0L, maxFee / 10000L).map { n =>
      SatoshisPerKiloByte(Satoshis(n))
    }
  }

  def satoshis: Gen[Satoshis] =
    for {
      int64 <- NumberGenerator.int64s
    } yield Satoshis(int64)

  def bitcoins: Gen[Bitcoins] =
    for {
      sat <- satoshis
    } yield Bitcoins(sat)

  def currencyUnit: Gen[CurrencyUnit] = Gen.oneOf(satoshis, bitcoins)

  def positiveSatoshis: Gen[Satoshis] =
    satoshis.suchThat(_ >= CurrencyUnits.zero)

  /**
    * Generates a postiive satoshi value that is 'realistic'. This current 'realistic' range
    * is from 0 to 1,000,000 bitcoin
    */
  def positiveRealistic: Gen[Satoshis] =
    Gen.choose(0, Bitcoins(1000000).satoshis.toLong).map { n =>
      Satoshis(n)
    }
}

object CurrencyUnitGenerator extends CurrencyUnitGenerator

trait LnCurrencyUnitGenerator {

  def milliBitcoin: Gen[MilliBitcoins] =
    for {
      amount <- Gen.choose(MilliBitcoins.min.toLong, MilliBitcoins.max.toLong)
    } yield MilliBitcoins(amount)

  def microBitcoin: Gen[MicroBitcoins] =
    for {
      amount <- Gen.choose(MicroBitcoins.min.toLong, MicroBitcoins.max.toLong)
    } yield MicroBitcoins(amount)

  def nanoBitcoin: Gen[NanoBitcoins] =
    for {
      amount <- Gen.choose(NanoBitcoins.min.toLong, NanoBitcoins.max.toLong)
    } yield NanoBitcoins(amount)

  def picoBitcoin: Gen[PicoBitcoins] =
    for {
      amount <- Gen.choose(PicoBitcoins.min.toLong, PicoBitcoins.max.toLong)
    } yield PicoBitcoins(amount)

  def lnCurrencyUnit: Gen[LnCurrencyUnit] =
    Gen.oneOf(milliBitcoin, microBitcoin, nanoBitcoin, picoBitcoin)

  def negativeLnCurrencyUnit: Gen[LnCurrencyUnit] =
    lnCurrencyUnit.suchThat(_ < LnCurrencyUnits.zero)
}

object LnCurrencyUnitGenerator extends LnCurrencyUnitGenerator
