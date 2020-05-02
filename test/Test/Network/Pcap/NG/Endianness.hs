{-# LANGUAGE TypeApplications #-}
module Test.Network.Pcap.NG.Endianness where

import           Test.Hspec
import           Test.QuickCheck
import           Test.Validity
import           Test.Validity.Enum
import           Test.Validity.Eq
import           Test.Validity.Ord

import           Network.Pcap.NG.Endianness

instance Arbitrary Endianness where
  arbitrary = elements [LittleEndian .. BigEndian]

instance GenUnchecked Endianness where

spec = describe "Network.Pcap.NG.Endianness" $ do
  eqSpec   @Endianness
  enumSpec @Endianness
