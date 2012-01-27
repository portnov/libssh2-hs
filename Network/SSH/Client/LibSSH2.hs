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
   retryIfNeeded,
   scpSendFile,
   scpReceiveFile,

   -- * Utilities
   socketConnect
  ) where

import Control.Monad
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

-- | Similar to Network.connectTo, but does not socketToHandle.
socketConnect :: String -> Int -> IO Socket
socketConnect hostname port = do
    proto <- getProtocolNumber "tcp"
    bracketOnError (socket AF_INET Stream proto) (sClose)
            (\sock -> do
              he <- getHostByName hostname
              connect sock (SockAddrInet (fromIntegral port) (hostAddress he))
              return sock)

-- | Execute some actions within SSH2 connection.
-- Uses public key authentication.
withSSH2 :: FilePath          -- ^ Path to known_hosts file
         -> FilePath          -- ^ Path to public key file
         -> FilePath          -- ^ Path to private key file
         -> String            -- ^ Remote user name
         -> String            -- ^ Remote host name
         -> Int               -- ^ Remote port number (usually 22)
         -> (Channel -> IO a) -- ^ Actions to perform on channel
         -> IO (Int, a)
withSSH2 known_hosts public private login hostname port fn =
  withSession hostname port $ \_ s -> do
    r <- checkHost s hostname port known_hosts
    print r
    a <- publicKeyAuthFile s login public private ""
    withChannel s $ fn

-- | Execute some actions within SSH2 session
withSession :: String                      -- ^ Remote host name
            -> Int                         -- ^ Remote port number (usually 22)
            -> (Handle -> Session -> IO a) -- ^ Actions to perform on handle and session
            -> IO a
withSession hostname port fn = do
  sock <- socketConnect hostname port
  handle <- socketToHandle sock ReadWriteMode 
  session <- initSession
  handshake session sock
  result <- fn handle session
  disconnectSession session "Done."
  freeSession session
  return result

--  | Check remote host against known hosts list
checkHost :: Session
          -> String             -- ^ Remote host name
          -> Int                -- ^ Remote port number (usually 22)
          -> FilePath           -- ^ Path to known_hosts file
          -> IO KnownHostResult
checkHost s host port path = do
  kh <- initKnownHosts s
  knownHostsReadFile kh path
  (hostkey, keylen, keytype) <- getHostKey s
  putStrLn $ "Host key: " ++ hostkey
  result <- checkKnownHost kh host port hostkey [TYPE_PLAIN, KEYENC_RAW]
  freeKnownHosts kh
  return result

-- | Execute some actions withing SSH2 channel
withChannel :: Session -> (Channel -> IO a) -> IO (Int, a)
withChannel s fn = do
  ch <- openChannelSession s
  -- waitSocket sock s
  result <- fn ch
  closeChannel ch
  exitStatus <- channelExitStatus ch
  freeChannel ch
  return (exitStatus, result)

-- | Read all data from the channel
readAllChannel :: Channel -> IO String
readAllChannel ch = do
    (sz, res) <- readChannel ch 0x400
    putStrLn $ "---- >> Read: " ++ show sz ++ " / " ++ show (length res)
    when (sz == 0) $
      putStrLn $ "  :: " ++ take 20 res ++ "..."
    if sz > 0
      then do
           rest <- readAllChannel ch
           putStrLn $ "---- >> Received: " ++ show (length rest)
           return $ res ++ rest
      else if sz < 0
             then throw (int2error sz)
             else return ""

-- | Send a file to remote host via SCP.
-- Returns size of sent data.
scpSendFile :: Session   
            -> Int       -- ^ File creation mode (0o777, for example)
            -> FilePath  -- ^ Path to local file
            -> FilePath  -- ^ Remote file path
            -> IO Integer
scpSendFile s mode local remote = do
  h <- openFile local ReadMode
  size <- hFileSize h
  ch <- scpSendChannel s remote mode (fromIntegral size) 0 0
  result <- writeChannelFromHandle s ch h
  hClose h
  closeChannel ch
  freeChannel ch
  return result

-- | Receive file from remote host via SCP.
-- Returns size of received data.
scpReceiveFile :: Session   --
               -> FilePath  -- ^ Remote file path
               -> FilePath  -- ^ Path to local file
               -> IO Integer
scpReceiveFile s remote local = do
  h <- openFile local WriteMode
  (ch, fileSize) <- scpReceiveChannel s remote
  result <- readChannelToHandle ch h fileSize
  hClose h
  closeChannel ch
  freeChannel ch
  return result

-- | Retry the action repeatedly, while it fails with EAGAIN.
-- This does matter if using nonblocking mode.
retryIfNeeded :: Handle -> Session -> IO a -> IO a
retryIfNeeded handle session action =
  action `E.catch` (\(e :: ErrorCode) ->
                      if e == EAGAIN
                        then do
                             waitSocket handle session
                             retryIfNeeded handle session action
                        else throw e )

