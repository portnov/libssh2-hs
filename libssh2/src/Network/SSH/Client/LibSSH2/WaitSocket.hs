-- | Block until a read or write operation on a socket would succeed
--
-- On most platforms this uses 'Control.Concurrent.threadWaitRead' or
-- 'Conctrol.Concurrent.threadWaitWrite', but on Windows we need to do
-- something different (TODO: not yet implemented on Windows). See
-- <http://hackage.haskell.org/trac/ghc/ticket/5797>.
module Network.SSH.Client.LibSSH2.WaitSocket 
  ( threadWaitRead
  , threadWaitWrite
  ) where

import qualified Control.Concurrent as Concurrent 
import Network.Socket
import System.Posix.Types 

threadWaitRead :: Socket -> IO ()
threadWaitRead = Concurrent.threadWaitRead . Fd . fdSocket

threadWaitWrite :: Socket -> IO ()
threadWaitWrite = Concurrent.threadWaitWrite . Fd . fdSocket
