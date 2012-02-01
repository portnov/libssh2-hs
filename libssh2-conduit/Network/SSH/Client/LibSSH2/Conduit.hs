{-# LANGUAGE FlexibleContexts #-}
module Network.SSH.Client.LibSSH2.Conduit where

import Control.Monad
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Resource
import Control.Monad.Trans.Control
import System.IO.Unsafe (unsafeInterleaveIO)
import Control.Concurrent.STM
import Data.Monoid
import Data.Conduit
-- import Data.Conduit.List as CL

import Network.SSH.Client.LibSSH2.Foreign
import Network.SSH.Client.LibSSH2

lazyConsume :: MonadBaseControl IO m => Source m a -> ResourceT m [a]
lazyConsume src0 = do
    go src0
  where

    go src = liftBaseOp_ unsafeInterleaveIO $ do
        res <- sourcePull src
        case res of
            Closed -> sourceClose src >> return []
            Open src' x -> do
                y <- go src'
                return $ x : y

sourceChannel :: Channel -> Source IO String
sourceChannel ch = src
  where
    src = Source pull close

    pull = do
        (sz, res) <- liftIO $ readChannel ch 0x400
        if sz > 0
            then return $ Open src res
            else return Closed

    close = return ()

splitLines :: Resource m => Conduit String m String
splitLines =
    conduitState id push close
  where
    push front bs' = return $ StateProducing leftover ls
      where
        bs = front bs'
        (leftover, ls) = getLines id bs

    getLines front bs
        | null bs = (id, front [])
        | null y = ((x ++), front [])
        | otherwise = getLines (front . (x:)) (drop 1 y)
      where
        (x, y) = break (== '\n') bs

    close front
        | null bs = return []
        | otherwise = return [bs]
      where
        bs = front ""

execCommand :: Maybe (TMVar Int) -> Session -> String -> IO [String]
execCommand var s cmd = do
  res <- runResourceT $ lazyConsume $ execCommandS var s cmd $= splitLines
  return res

execCommands :: Maybe (TMVar Int) -> Session -> [String] -> IO [String]
execCommands var s cmds = do
  let srcs = [execCommandS (v i) s cmd | (i, cmd) <- zip [1..] cmds ]
      v i | i == length cmds = var
          | otherwise        = Nothing
  res <- runResourceT $ lazyConsume $ mconcat srcs $= splitLines
  return res

execCommandS :: Maybe (TMVar Int) -> Session -> String -> Source IO String
execCommandS var s command =
  Source {
      sourcePull = do
        (key, st) <- withIO start (const $ return ())
        pull key st 
    , sourceClose = return () }
  where
    start = do
      ch <- openChannelSession s
      return ch
    
    next key ch =
      Source (pullAnswer key ch) $ do
          return ()
          --liftIO $ cleanup ch
          --release key

    pullAnswer key ch = do
      (sz, res) <- liftIO $ readChannel ch 0x400
      if sz > 0
        then return $ Open (next key ch) res
        else do
             liftIO $ cleanup ch
             return Closed

    pull key ch = do
      liftIO $ channelExecute ch command
      pullAnswer key ch

    cleanup ch = do
      closeChannel ch
      case var of
        Nothing -> return ()
        Just v  -> do
                   exitStatus <- channelExitStatus ch
                   atomically $ putTMVar v exitStatus
      closeChannel ch
      freeChannel ch
      return ()

