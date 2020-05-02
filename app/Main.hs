module Main where

import           Conduit
import           Control.Lens
import           Data.Conduit.List         (consume)
import           System.Environment

import qualified Data.WordString32.Conduit as WSC
import           Network.Pcap.NG.Block

main :: IO ()
main = do
  getArgs >>= mapM_ parse

parse filename = runConduitRes
               $ WSC.sourceFile filename .| blockConduit .| blockTypes .| consume

blockTypes = awaitForever $ \block -> do
                               liftIO $ print $ block ^. blockType
                               yield (block ^. blockType)
