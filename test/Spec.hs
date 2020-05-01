{-# LANGUAGE NamedFieldPuns      #-}
{-# LANGUAGE ScopedTypeVariables #-}
import           Control.Lens                 ((^.))
import           Control.Monad                (forM, forM_)
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Resource
import           Data.Conduit
import           Data.Conduit.Cereal          (sinkGet)
import qualified Data.Conduit.Combinators     as C (head, sourceFile)
import           Data.Conduit.List            (consume)
import           Data.List                    (isPrefixOf)
import           Data.Serialize               (get)
import           System.Directory
import           System.FilePath.Posix        (takeExtension, takeFileName,
                                               (</>))
import           System.IO                    (hPutStrLn, stderr)
import           Test.Hspec
import           Test.Hspec.Core.Runner
import           Test.QuickCheck

import qualified Data.WordString32.Conduit    as WSC
import           Network.Pcap.Ng
import           Network.Pcap.NG.BlockType

import qualified Test.Data.WordString32       as Test.WordString32 (spec)

main :: IO ()
main = hspecWith config spec
  where
    config = defaultConfig {
                 configColorMode     = ColorAlways
               , configFailureReport = Just "failure.log"
               , configDiff          = True
               }


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
             $ liftIO . hPutStrLn stderr . show . (^. blockType)

testPcapFile :: FilePath -> Spec
testPcapFile         filename =
    it filename $ do
      parse filename >>= (`shouldMatchList` [])

testPcapFileSections :: FilePath -> [BlockType] -> Spec
testPcapFileSections filename bts =
    it filename $
      parse filename >>= (`shouldMatchList` bts)

testPcapFilePrefixAndCount :: FilePath -> [BlockType] -> Int -> Spec
testPcapFilePrefixAndCount filename prefix count = do
  describe filename $ do
    it (filename <> " has correct prefix") $ do
      actualBts <- parse filename
      actualBts `shouldSatisfy` (isPrefixOf prefix)
    it (filename <> "has correct number of packets") $ do
      actualBts <- parse filename
      length actualBts `shouldBe` count

blockTypes = awaitForever $ \block -> do
                               liftIO $ print $ block ^. blockType
                               yield (block ^. blockType)

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
  describe "Data.WordString32" $
    Test.WordString32.spec
  describe "Block recognition" $ do
    return ()
  fdescribe "Pcap.org examples" $ do
    files <- runIO $ filesWithExts "test/pcapng.org" [".ntar", ".pcapng"]
    runIO $ putStrLn $ "Test files found: " <> show files
    describe "parse first block" $
      forM_ files testPcapFileHeader
    describe "parse all blocks" $ do
      testPcapFileSections "test/pcapng.org/dhcp.pcapng" $
        [SectionHeader, IfDesc, EnhancedPacket, EnhancedPacket, EnhancedPacket, EnhancedPacket]
      testPcapFilePrefixAndCount "test/pcapng.org/pcap-ng_Wi-Fi_Bluetooth_USB_Cooked_timestamps_issue_1.ntar"
        [SectionHeader,IfDesc,EnhancedPacket] 224
      testPcapFileSections "test/pcapng.org/dhcp_big_endian.pcapng" $
        [SectionHeader, IfDesc, NameResolution] <> replicate 4 EnhancedPacket
      testPcapFileSections "test/wireshark/dhcp-nanosecond.pcapng" $
        [SectionHeader, IfDesc] <> replicate 4 EnhancedPacket
      testPcapFileSections "test/wireshark/dmgr.pcapng" $
        [SectionHeader, IfDesc] <> replicate 42 EnhancedPacket
      testPcapFileSections "test/wireshark/http2-brotli.pcapng" $
        [SectionHeader, IfDesc, DecryptionSecrets] <> replicate 25 EnhancedPacket
      testPcapFileSections "test/wireshark/ikev2-decrypt-aes256cbc.pcapng" $
        [SectionHeader, IfDesc, IfDesc] <> replicate 4 EnhancedPacket <> [IfStats, IfStats]
      testPcapFileSections "test/wireshark/packet-h2-14_headers.pcapng" $
        [SectionHeader, IfDesc] <> replicate 15 EnhancedPacket <> [IfStats]
      testPcapFileSections "test/wireshark/tls12-dsb.pcapng" $
        [SectionHeader, IfDesc, DecryptionSecrets] <> replicate 9 EnhancedPacket
                            <> [DecryptionSecrets] <> replicate 8 EnhancedPacket
      testPcapFileSections "test/wireshark/dhcp.pcapng" $ [SectionHeader, IfDesc] <> replicate 4 EnhancedPacket
      testPcapFileSections "test/wireshark/dtls12-aes128ccm8-dsb.pcapng" $
        [SectionHeader, IfDesc, DecryptionSecrets] <> replicate 13 EnhancedPacket
      testPcapFileSections "test/wireshark/http-brotli.pcapng" $
        [SectionHeader, IfDesc] <> replicate 10 EnhancedPacket <> [IfStats]
      testPcapFileSections "test/wireshark/ikev2-decrypt-aes256ccm16.pcapng" $
        [SectionHeader,IfDesc,IfDesc] <> replicate 4 EnhancedPacket <> replicate 2 IfStats
      testPcapFileSections "test/wireshark/sip.pcapng" $ [SectionHeader,IfDesc] <> replicate 6 EnhancedPacket
      testPcapFileSections "test/wireshark/wireguard-ping-tcp-dsb.pcapng" $
        [SectionHeader, IfDesc, DecryptionSecrets] <> replicate 22 EnhancedPacket
      testPcapFileSections "test/pcapng.org/dhcp_little_endian.pcapng" $
        [SectionHeader, IfDesc, NameResolution] <> replicate 4 EnhancedPacket
      testPcapFileSections "test/pcapng.org/many_interfaces.pcapng" $
        [SectionHeader] <> replicate 11 IfDesc
                        <> replicate 64 EnhancedPacket
                        <> [NameResolution]
                        <> replicate 11 IfStats
      testPcapFileSections "test/pcapng.org/http.bigendian.ntar" $
        []
      testPcapFileSections "test/pcapng.org/icmp2.ntar" $
        []
    xdescribe "parse entire file of blocks" $
      forM_ files testPcapFile
