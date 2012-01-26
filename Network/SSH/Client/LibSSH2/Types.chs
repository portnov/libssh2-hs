{-# LANGUAGE ForeignFunctionInterface #-}

#include <libssh2.h>

{# context lib="ssh2" prefix="libssh2" #}

module Network.SSH.Client.LibSSH2.Types
  (Session,
   KnownHosts,
   Channel,
   IsPointer (..)
  ) where

import Foreign
import Foreign.Ptr

class IsPointer p where
  fromPointer :: Ptr () -> p
  toPointer :: p -> Ptr ()

{# pointer *SESSION as Session newtype #}

instance IsPointer Session where
  fromPointer p = Session (castPtr p)
  toPointer (Session p) = castPtr p

{# pointer *KNOWNHOSTS as KnownHosts newtype #}

instance IsPointer KnownHosts where
  fromPointer p = KnownHosts (castPtr p)
  toPointer (KnownHosts p) = castPtr p

{# pointer *CHANNEL as Channel newtype #}

instance IsPointer Channel where
  fromPointer p = Channel (castPtr p)
  toPointer (Channel p) = castPtr p

