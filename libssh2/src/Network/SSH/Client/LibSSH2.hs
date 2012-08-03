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
   scpSendFile,
   scpReceiveFile,
   runShellCommands,
   execCommands,

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
         -> (Session -> IO a) -- ^ Actions to perform on session 
         -> IO a 
withSSH2 known_hosts public private login hostname port fn =
  withSession hostname port $ \s -> do
    r <- checkHost s hostname port known_hosts
    publicKeyAuthFile s login public private ""
    fn s

-- | Execute some actions within SSH2 session
withSession :: String            -- ^ Remote host name
            -> Int               -- ^ Remote port number (usually 22)
            -> (Session -> IO a) -- ^ Actions to perform on handle and session
            -> IO a
withSession hostname port fn = do
  sock <- socketConnect hostname port
  session <- initSession
  setBlocking session False
  handshake session sock
  result <- fn session
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
  result <- checkKnownHost kh host port hostkey [TYPE_PLAIN, KEYENC_RAW]
  freeKnownHosts kh
  return result

-- | Execute some actions withing SSH2 channel
withChannel :: Session -> (Channel -> IO a) -> IO (Int, a)
withChannel s = withChannelBy (openChannelSession s) id 

-- | Read all data from the channel
readAllChannel :: Channel -> IO String
readAllChannel ch = do
    (sz, res) <- readChannel ch 0x400
    if sz > 0
      then do
           rest <- readAllChannel ch
           return $ res ++ rest
      else return ""

runShellCommands :: Session -> [String] -> IO (Int, [String])
runShellCommands s commands = withChannel s $ \ch -> do
  requestPTY ch "linux"
  channelShell ch
  hello <- readAllChannel ch
  out <- forM commands $ \cmd -> do
             writeChannel ch (cmd ++ "\n")
             r <- readAllChannel ch
             return r
  channelSendEOF ch
  return out

execCommands :: Session -> [String] -> IO (Int, [String])
execCommands s commands = withChannel s $ \ch -> 
  forM commands $ \cmd -> do
      channelExecute ch cmd
      readAllChannel ch


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
  (_, result) <- withChannelBy (scpSendChannel s remote mode (fromIntegral size) 0 0) id $ \ch ->
    writeChannelFromHandle s ch h
  hClose h
  return result 

-- | Receive file from remote host via SCP.
-- Returns size of received data.
scpReceiveFile :: Session   --
               -> FilePath  -- ^ Remote file path
               -> FilePath  -- ^ Path to local file
               -> IO Integer
scpReceiveFile s remote local = do
  h <- openFile local WriteMode
  (_, result) <- withChannelBy (scpReceiveChannel s remote) fst $ \(ch, fileSize) -> do  
    readChannelToHandle ch h fileSize
  hClose h
  return result

-- | Generalization of 'withChannel'
withChannelBy :: IO a            -- ^ Create a channel (and possibly other stuff)
              -> (a -> Channel)  -- ^ Extract the channel from "other stuff"
              -> (a -> IO b)     -- ^ Actions to execute on the channel 
              -> IO (Int, b)     -- ^ Channel exit status and return value
withChannelBy createChannel extractChannel actions = do
  stuff <- createChannel
  let ch = extractChannel stuff
  result <- actions stuff 
  closeChannel ch
  exitStatus <- channelExitStatus ch
  freeChannel ch
  return (exitStatus, result)

