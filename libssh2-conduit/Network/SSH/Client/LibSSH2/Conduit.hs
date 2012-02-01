
module Network.SSH.Client.LibSSH2.Conduit where

import Control.Monad
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Resource
import Control.Concurrent.STM
import Data.Conduit

import Network.SSH.Client.LibSSH2.Foreign
import Network.SSH.Client.LibSSH2

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
splitLines = conduitState "" push close
  where
    push st input =
      case lines input of
        [] -> return $ StateProducing "" [st]
        [s1,s2] -> return $ StateProducing s2 [s1]
        (h:t) -> return $ StateProducing (last t) ((st ++ h): init t)

    close st = return [st]

execCommand :: Session -> String -> Source IO String
execCommand s cmd = execCommandS s cmd $= splitLines

execCommandS :: Session -> String -> Source IO String
execCommandS s command =
  Source {
      sourcePull = do
        (key, ch) <- withIO start cleanup
        pull key ch
    , sourceClose = return () }
  where
    start = do
      ch <- openChannelSession s
      return ch
    
    next key ch =
      Source (pullAnswer key ch) (release key)

    pullAnswer key ch = do
      (sz, res) <- liftIO $ readChannel ch 0x400
      if sz > 0
        then return $ Open (next key ch) res
        else return Closed

    pull key ch = do
      liftIO $ channelExecute ch command
      pullAnswer key ch

    cleanup ch = do
      closeChannel ch
      exitStatus <- channelExitStatus ch
      closeChannel ch
      freeChannel ch
      return ()

