import           Test.Hspec
import           Test.QuickCheck

import           Network.Pcap.Ng

main :: IO ()
main = hspec spec

spec = do
  describe "Block recognition" $ do
    return ()
  describe "Pcap.org examples" $ do
    it "Does nothing" $ True `shouldBe` True
