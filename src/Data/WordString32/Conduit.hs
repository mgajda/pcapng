module Data.WordString32.Conduit(
    sourceFile
  , sinkFile
  , atLeast
  ) where

import           Control.Monad.Trans.Resource (MonadResource(..))
import qualified Data.ByteString     as BS
import qualified Data.WordString32   as WS
import           Data.Conduit                 (mapInput, mapOutput, ConduitT, (.|), await, yield )
import qualified Data.Conduit.Binary as C
import qualified Data.Conduit.List   as C

import Debug.Trace(trace)

sourceFile :: (MonadResource m
              ,MonadFail     m)
           =>  FilePath
           ->  ConduitT () WS.WordString m ()
sourceFile filepath = C.sourceFile filepath .| go
  where
    go = do
      bs <- trace "sourceFile chunk" $ await
      case bs of
        Nothing -> return ()
        Just bs | BS.length bs `mod` 4 /= 0 -> do
          -- OMG, why do we need to do this (hspec error)
          let msg = "Incorrect PCAP file - not aligned to 4 byte boundary: " <> show (BS.length bs)
          trace msg $
            yield $ WS.fromBS $ BS.take ((BS.length bs `div` 4)*4) bs
          return () -- fail after partial read
        Just bs -> yield $ WS.fromBS bs

sinkFile :: MonadResource m => FilePath -> ConduitT WS.WordString () m ()
sinkFile filepath = C.map WS.toBS .| C.sinkFile filepath

-- | Make sure that we give chunks of at least N words
--
--   This conduit has a hidden state, so cannot be easily aborted.
-- NOTE: example of how conduit could get better by feedback upstream (needed input size)
-- WARNING: may lead to suboptimal performance if make misaligned reads
atLeast  :: MonadFail                            m
         => Int
         -> ConduitT WS.WordString WS.WordString m ()
atLeast n = go WS.empty
  where
    go rest = do
      maybeChunk <- await
      case maybeChunk of
        Nothing | WS.null rest -> return ()
        Nothing                -> fail
                                $ mconcat ["Not enough bytes to satisfy atLeast: ",
                                           show $ WS.length rest, " wanting: ", show n]
        Just chunk | WS.length rest + WS.length chunk >= n ->
          trace "long chunk" $
            yield $ rest <> chunk
        Just shortChunk -> trace "short chunk" $ go $ rest <> shortChunk

