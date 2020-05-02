{-# LANGUAGE TypeApplications #-}
module Test.Network.Pcap.NG.BlockType(spec) where

import           Network.Pcap.NG.BlockType
import           Test.Hspec
import           Test.QuickCheck
import           Test.Validity
import           Test.Validity.Enum
import           Test.Validity.Eq
import           Test.Validity.Ord

instance Arbitrary BlockType where
  arbitrary = genValid
  shrink    = shrinkValid

instance GenUnchecked BlockType where
  genUnchecked      = toEnum <$> arbitrary
  shrinkUnchecked _ = []

instance Validity BlockType where
  validate (Reserved   c) = invalid $ "Reserved block type " <> show c
  validate (Corruption c) = invalid $ "Corrupt block type " <> show c
  validate  _             = valid

instance GenValid BlockType where

spec = describe "Network.Pcap.NG.BlockType" $ do
  eqSpec   @BlockType
  ordSpec  @BlockType
  enumSpec @BlockType
