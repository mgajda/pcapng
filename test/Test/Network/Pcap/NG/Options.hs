{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
module Test.Network.Pcap.NG.Options where

import           Network.Pcap.NG.Options

import           Data.WordString32               as WS

import qualified Data.ByteString                 as BS
import qualified Data.ByteString.Arbitrary       as ABS
import           Data.Typeable
import           Test.Hspec
import           Test.Hspec.QuickCheck           (prop)
import           Test.QuickCheck
import           Test.QuickCheck.Arbitrary
import           Test.QuickCheck.Gen
import           Test.Validity
import           Test.Validity.Arbitrary
import           Test.Validity.Enum
import           Test.Validity.Eq
import           Test.Validity.Functions.Inverse
import           Test.Validity.Monoid
import           Test.Validity.Ord
import           Test.Validity.Utils

instance Arbitrary ReceptionType where
  arbitrary = elements [Unspecified
                     .. Promiscuous]

instance Validity ReceptionType where

instance GenValid ReceptionType where

instance GenUnchecked ReceptionType where

spec = do
  fdescribe "ReceptionType" $ do
    eqSpec   @ReceptionType
    ordSpec  @ReceptionType
    enumSpec @ReceptionType
