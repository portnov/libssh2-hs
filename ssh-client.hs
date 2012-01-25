
import System.Environment
import System.FilePath
import Network.SSH.Client.Foreign
import Network.SSH.Client.LibSSH2

main = do
  args <- getArgs
  case args of
    [user, host, port, cmd] -> runCommand user host (read port) cmd
    _ -> putStrLn "Synopsis: ssh-client USERNAME HOSTNAME PORT COMMAND"

runCommand login host port command = do
  initialize True
  home <- getEnv "HOME"
  let known_hosts = home </> ".ssh" </> "known_hosts"
      public = home </> ".ssh" </> "id_rsa.pub"
      private = home </> ".ssh" </> "id_rsa"
  withSSH2 known_hosts public private login host port $ \ch -> do
      channelExecute ch command
      result <- readAllChannel ch
      print result
