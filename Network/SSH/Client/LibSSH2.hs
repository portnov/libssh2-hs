
module Network.SSH.Client.LibSSH2 where

import Control.Exception
import Network
import Network.BSD
import Network.Socket
import System.IO

import Network.SSH.Client.Foreign

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

withSession :: String -> Int -> (Session -> IO a) -> IO a
withSession hostname port fn = do
  sock <- socketConnect hostname port
  initialize True
  session <- initSession
  handshake session sock
  result <- fn session
  disconnectSession session "Done."
  freeSession session
  return result

checkHost :: Session -> String -> Int -> FilePath -> IO KnownHostResult
checkHost s host port path = do
  kh <- initKnownHosts s
  knownHostsReadFile kh path
  (hostkey, keylen, keytype) <- getHostKey s
  result <- checkKnownHost kh host port hostkey [TYPE_PLAIN, KEYENC_RAW]
  freeKnownHosts kh
  return result

withChannel :: Socket -> Session -> (Channel -> IO a) -> IO a
withChannel sock s fn = do
  ch <- openChannelSession s
  -- waitSocket sock s
  result <- fn ch
  closeChannel ch
  freeChannel ch
  return result

