module Data.WordString32.Conduit(
    sourceFile
  , sinkFile
  ) where

import           Control.Monad.Trans.Resource (MonadResource(..))
import qualified Data.WordString32   as WS
import           Data.Conduit                 (mapInput, mapOutput, ConduitT, (.|), await, yield )
import qualified Data.Conduit.Binary as C
import qualified Data.Conduit.List   as C

sourceFile :: MonadResource m => FilePath -> ConduitT () WS.WordString m ()
sourceFile filepath = mapOutput WS.fromBS $ C.sourceFile filepath

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
        Nothing                -> fail $ "Not enough bytes to satisfy atLeast: " <> show (WS.length rest) <> " wanting: " <> show n
        Just chunk | WS.length rest + WS.length chunk >= n ->
          yield $ rest <> chunk
        Just shortChunk -> go $ rest <> shortChunk

