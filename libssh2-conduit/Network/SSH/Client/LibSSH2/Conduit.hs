{-# LANGUAGE FlexibleContexts #-}
module Network.SSH.Client.LibSSH2.Conduit
  (sourceChannel,
   splitLines,
   CommandsHandle,
   execCommand,
   getReturnCode
  ) where

import Control.Monad
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Resource
import Control.Monad.Trans.Control
import System.IO.Unsafe (unsafeInterleaveIO)
import Control.Concurrent.STM
import Data.Monoid
import Data.Conduit
import Data.Conduit.Lazy

import Network.SSH.Client.LibSSH2.Foreign
import Network.SSH.Client.LibSSH2

-- | Read all contents of libssh2's Channel.
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

-- | Similar to Data.Conduit.Binary.lines, but for Strings.
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

-- | Execute one command and read it's output lazily.
-- If first argument is True, then you *must* get return code
-- using getReturnCode on returned CommandsHandle. Moreover,
-- you *must* guarantee that getReturnCode will be called
-- only when all command output will be read.
execCommand :: Bool                          -- ^ Set to True if you want to get return code when command will terminate.
            -> Session
            -> String                        -- ^ Command
            -> IO (Maybe CommandsHandle, Source IO String) 
execCommand b s cmd = do
  (ch, channel) <- initCH b s
  let src = execCommandS ch channel cmd $= splitLines
  return (if b then Just ch else Nothing, src)

-- execCommands :: Bool -> Session -> [String] -> IO [String]
-- execCommands b s cmds = do
--   let srcs = [execCommandS (v i) s cmd | (i, cmd) <- zip [1..] cmds ]
--       v i | i == length cmds = var
--           | otherwise        = Nothing
--   res <- runResourceT $ lazyConsume $ mconcat srcs $= splitLines
--   return res

-- | Handles channel opening and closing.
data CommandsHandle = CommandsHandle {
  chReturnCode :: Maybe (TMVar Int),
  chChannel :: TMVar Channel,
  chChannelClosed :: TVar Bool }

initCH :: Bool -> Session -> IO (CommandsHandle, Channel)
initCH False s = do
  c <- newTVarIO False
  ch <- newEmptyTMVarIO
  channel <- openCH ch s
  return (CommandsHandle Nothing ch c, channel)
initCH True s = do
  r <- newEmptyTMVarIO
  c <- newTVarIO False
  ch <- newEmptyTMVarIO
  channel <- openCH ch s
  return (CommandsHandle (Just r) ch c, channel)

openCH :: TMVar Channel -> Session -> IO Channel
openCH var s = do
      ch <- openChannelSession s
      atomically $ putTMVar var ch
      return ch

-- | Get return code for previously run command.
-- It will fail if command was run using execCommand False.
-- Should be called only when all command output is read.
getReturnCode :: CommandsHandle -> IO Int
getReturnCode ch = do
  c <- atomically $ readTVar (chChannelClosed ch)
  if c
    then do
      case chReturnCode ch of
        Nothing -> fail "Channel already closed and no exit code return was set up for command."
        Just v -> atomically $ takeTMVar v
    else do
      channel <- atomically $ takeTMVar (chChannel ch)
      cleanupChannel ch channel
      atomically $ writeTVar (chChannelClosed ch) True
      case chReturnCode ch of
        Nothing -> fail "No exit code return was set up for commnand."
        Just v  -> do
                   rc <- atomically $ takeTMVar v
                   return rc
    
execCommandS :: CommandsHandle -> Channel -> String -> Source IO String
execCommandS var channel command =
  Source {
      sourcePull = pull channel 
    , sourceClose = return () }
  where
    
    next ch =
      Source (pullAnswer ch) $ do
          return ()
          --liftIO $ cleanupChannel var ch

    pullAnswer ch = do
      (sz, res) <- liftIO $ readChannel ch 0x400
      if sz > 0
        then return $ Open (next ch) res
        else do
             liftIO $ cleanupChannel var ch
             return Closed

    pull ch = do
      liftIO $ channelExecute ch command
      pullAnswer ch

-- | Close Channel and write return code
cleanupChannel :: CommandsHandle -> Channel -> IO ()
cleanupChannel ch channel = do
  c <- atomically $ readTVar (chChannelClosed ch)
  when (not c) $ do
    closeChannel channel
    case chReturnCode ch of
      Nothing -> return ()
      Just v  -> do
                 exitStatus <- channelExitStatus channel
                 atomically $ putTMVar v exitStatus
    closeChannel channel
    freeChannel channel
    atomically $ writeTVar (chChannelClosed ch) True
    return ()

