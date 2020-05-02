{-# LANGUAGE TypeApplications #-}
module Test.Data.WordString32(spec) where

import           Data.WordString32         as WS

import qualified Data.ByteString           as BS
import qualified Data.ByteString.Arbitrary as ABS
import           Test.Hspec
import           Test.Hspec.QuickCheck     (prop)
import           Test.QuickCheck
import           Test.QuickCheck.Arbitrary
import           Test.QuickCheck.Gen
import           Test.Validity
import           Test.Validity.Arbitrary
import           Test.Validity.Eq
import           Test.Validity.Monoid
import           Test.Validity.Ord

instance Arbitrary WordString where
  arbitrary = do
    len <- (4*) <$> arbitrary -- choose(1,16)
    fromBS <$> ABS.fastRandBs len
  shrink    = shrinkWS

instance Validity WordString where
  validate ws = valid
  {-validate (WS ptr ofs len) = do
        check (ofs <= len) "Offset is less than WordString length"
     <> check (len >= 0)  "Length of the WordString is greater than zero"
     <> check (ofs >= 0)  "Offset is not less than zero"-}

instance GenUnchecked WordString where
  genUnchecked = arbitrary
  shrinkUnchecked = shrinkWS

shrinkWS ws =
       ((`WS.take` ws) <$> [1..WS.length ws])
    <> ((`WS.drop` ws) <$> [1..WS.length ws])

instance GenValid WordString where
  genValid = arbitrary
  shrinkValid = shrinkWS

spec :: Spec
spec = describe "Data.WordString" $ do
  eqSpec                      @WordString
  ordSpec                     @WordString
  monoidSpec                  @WordString
  describe "drop" $ do
    prop "decreases length" $ \ws (Positive d) ->
      d < WS.length ws && d >= 0 ==>
        WS.length (WS.drop d ws) == WS.length ws - d
    prop "shifts indices after N-th" $ \ws (Positive d) (Positive i) ->
      i+d < WS.length ws ==>
        WS.index ws (i+d) == WS.index (WS.drop d ws) i
    prop "of empty" $ \(Positive i) ->
      WS.take i empty == empty
  describe "take" $ do
    prop "decreases length" $ \ws d ->
      d < WS.length ws && d >= 0 ==>
        WS.length (WS.take d ws) `shouldBe` d
    prop "preserves initial indices" $ \ws (Positive d) (Positive i) ->
      d < WS.length ws && i < d ==>
        WS.index (WS.take d ws) i `shouldBe` WS.index ws i
    prop "of empty" $ \(Positive i) ->
      WS.take i empty == empty
  describe "append" $ do
    prop "length sums up" $ \ws1 ws2 ->
      WS.length (ws1 <> ws2) `shouldBe`
        WS.length ws1 + WS.length ws2
    prop "preserves initial indices" $ \ws1 ws2 (Positive i) ->
      i < WS.length ws1 ==>
        WS.index ws1 i `shouldBe` WS.index (ws1 <> ws2) i
    prop "shifts indices in the second argument" $ \ws1 ws2 (Positive i) ->
      i < WS.length ws2 ==>
        WS.index ws2 i `shouldBe` WS.index (ws1 <> ws2) (WS.length ws1 + i)
  describe "length" $ do
    it "of empty is zero" $ WS.length WS.empty == 0
    prop "null is always empty" $ \ws -> WS.null ws `shouldBe` WS.length ws == 0
  --arbitraryGeneratesOnlyValid @WordString
