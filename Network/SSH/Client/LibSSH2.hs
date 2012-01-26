{-# LANGUAGE ScopedTypeVariables #-}
module Network.SSH.Client.LibSSH2
  (-- * Types
   Session, Channel, KnownHosts,

   -- * Functions
   withSSH2,
   withSession,
   withChannel,
   checkHost,
   readAllChannel,
   retryIfNeeded
  ) where

import Control.Exception as E
import Network
import Network.BSD
import Network.Socket
import System.IO

import Network.SSH.Client.LibSSH2.Types
import Network.SSH.Client.LibSSH2.Errors
import Network.SSH.Client.LibSSH2.Foreign

-- | Check if handle is ready for reading in 10 seconds.
waitSocket :: Handle -> Session -> IO Bool
waitSocket h s = do
  dirs <- blockedDirections s
  if INBOUND `elem` dirs
    then hWaitForInput h (10*1000)
    else return True

socketConnect :: String -> Int -> IO Socket
socketConnect hostname port = do
    proto <- getProtocolNumber "tcp"
    bracketOnError (socket AF_INET Stream proto) (sClose)
            (\sock -> do
              he <- getHostByName hostname
              connect sock (SockAddrInet (fromIntegral port) (hostAddress he))
              return sock)

withSSH2 :: FilePath -> FilePath -> FilePath -> String -> String -> Int -> (Channel -> IO a) -> IO a
withSSH2 known_hosts public private login hostname port fn =
  withSession hostname port $ \_ s -> do
    r <- checkHost s hostname port known_hosts
    print r
    a <- publicKeyAuthFile s login public private ""
    withChannel s $ fn

withSession :: String -> Int -> (Handle -> Session -> IO a) -> IO a
withSession hostname port fn = do
  sock <- socketConnect hostname port
  handle <- socketToHandle sock ReadWriteMode 
  session <- initSession
  handshake session sock
  result <- fn handle session
  disconnectSession session "Done."
  freeSession session
  return result

checkHost :: Session -> String -> Int -> FilePath -> IO KnownHostResult
checkHost s host port path = do
  kh <- initKnownHosts s
  knownHostsReadFile kh path
  (hostkey, keylen, keytype) <- getHostKey s
  putStrLn $ "Host key: " ++ hostkey
  result <- checkKnownHost kh host port hostkey [TYPE_PLAIN, KEYENC_RAW]
  freeKnownHosts kh
  return result

withChannel :: Session -> (Channel -> IO a) -> IO a
withChannel s fn = do
  ch <- openChannelSession s
  -- waitSocket sock s
  result <- fn ch
  closeChannel ch
  freeChannel ch
  return result

readAllChannel :: Channel -> IO String
readAllChannel ch = do
    (sz, res) <- readChannel ch 0x400
    if sz > 0
      then do
           rest <- readAllChannel ch
           return $ res ++ rest
      else return ""

retryIfNeeded :: Handle -> Session -> IO a -> IO a
retryIfNeeded handle session action =
  action `E.catch` (\(e :: ErrorCode) ->
                      if e == EAGAIN
                        then do
                             waitSocket handle session
                             retryIfNeeded handle session action
                        else throw e )

