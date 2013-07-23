{-# LANGUAGE BangPatterns #-}

import Control.Monad
import Control.Monad.Trans.Resource
import Control.Concurrent.STM
import Data.Conduit
import Data.Conduit.Lazy
import System.Environment
import System.FilePath
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import Codec.Binary.UTF8.String

import Network.SSH.Client.LibSSH2.Foreign
import Network.SSH.Client.LibSSH2.Conduit
import Network.SSH.Client.LibSSH2

main = do
  args <- getArgs
  case args of
    [user, host, port, cmd]  -> ssh user host (read port) cmd
    _ -> putStrLn "Synopsis: ssh-client USERNAME HOSTNAME PORT COMMAND"

ssh login host port command = do
  initialize True
  home <- getEnv "HOME"
  let known_hosts = home </> ".ssh" </> "known_hosts"
      public = home </> ".ssh" </> "id_rsa.pub"
      private = home </> ".ssh" </> "id_rsa"
  withSession host port $ \session -> do
    r <- checkHost session host port known_hosts
    publicKeyAuthFile session login public private ""
    (Just ch, !src) <- execCommand True session command
    res <- runResourceT $ returnStrict =<< lazyConsume src
    forM res C8.putStrLn
    rc <- getReturnCode ch
    putStrLn $ "Exit code: " ++ show rc
  exit

returnStrict !x = return x
