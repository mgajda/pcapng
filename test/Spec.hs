{-# language NamedFieldPuns      #-}
{-# language ScopedTypeVariables #-}
import           Test.Hspec -- hiding (shouldReturn, shouldBe, shouldSatisfy)
import           Test.Hspec.Core.Runner
import           Test.QuickCheck
import           Data.Conduit
import qualified Data.Conduit.Combinators as C(sourceFile, head)
import           Data.Conduit.Cereal(sinkGet)
import           Data.Conduit.List(consume)
import           Data.Serialize(get)
import           System.Directory
import           System.FilePath.Posix(takeFileName, takeExtension, (</>))
import           Control.Monad(forM, forM_)
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Resource
import           Control.Lens((^.))

import qualified Data.WordString32.Conduit as WSC
import           Network.Pcap.Ng
import           Network.Pcap.NG.BlockType


main :: IO ()
main = hspecWith config spec
  where
    config = defaultConfig {
                 configColorMode     = ColorAlways
               , configFailureReport = Just "failure.log"
               , configDiff          = True
               }

{-
hspecConfig = defaultConfig { configFormatter = configFormatter defaultConfig { exampleFailed = failureFormatter }}
  where
    failureFormatter path result = do
      let super = exampleFailed $ configFormatter defaultConfig
      super path result
      getFailMessages >>= either formatException writeLine
 -}


filesWithExts ::      FilePath -- ^ Directory to search
              ->     [String  ]-- ^ Extensions list
              ->  IO [FilePath]
filesWithExts dirName exts =
    map (dirName </>) . filter matchExt <$> getDirectoryContents dirName
  where
    matchExt = (`elem` exts)
             . takeExtension

consumeBlock :: MonadIO m => ConduitT Block Void m ()
consumeBlock = awaitForever
             $ liftIO . print . (^. blockType)

testPcapFile :: FilePath -> Spec
testPcapFile         filename =
    it filename $ do
      parse filename >>= (`shouldMatchList` [])

blockTypes = awaitForever $ \block -> yield (block ^. blockType)

parse filename = runConduitRes
               $ WSC.sourceFile filename .| pcapNgConduit2 .| blockTypes .| consume

{-
parse :: FilePath -> IO ()
parse filename = runConduitRes
               $ WSC.sourceFile filename .| pcapNgConduit2 .| consumeBlock
 -}

testPcapFileHeader :: FilePath -> Spec
testPcapFileHeader filename =
                it filename $
       parseHeader filename `shouldReturn` SectionHeader

parseHeader filename = do
  header :: Maybe Block <- runConduitRes
                         $ WSC.sourceFile filename .| pcapNgConduit2 .| C.head
  case header of
    Just h  -> do
      print  $ h ^. blockType
      return $ h ^. blockType
    Nothing -> error "No blocktype here!"

spec = do
  describe "Block recognition" $ do
    return ()
  describe "Pcap.org examples" $ do
    files <- runIO $ filesWithExts "test/pcapng.org" [".ntar", ".pcapng"]
    runIO $ putStrLn $ "Test files found: " <> show files
    describe "parse first block" $
      forM_ files testPcapFileHeader
    describe "parse entire file of blocks" $
      forM_ files testPcapFile

