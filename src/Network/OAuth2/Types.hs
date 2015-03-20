module Network.OAuth2.Types
  where

import Network.OAuth2.Token
import Network.OAuth2.CSRFToken
import Network.HTTP.Conduit
import Control.Monad.Except
import Control.Monad.State

data OAuth2WebServerFlow = OAuth2WebServerFlow
    { token :: !CSRFToken,
      clientSecret :: !String,
      scope :: ![String],
      redirectUri :: !String,
      userAgent :: !String,
      authUri :: !String,
      tokenUri :: !String,
      revokeUri :: !String,
      loginHint :: !String,
      deviceUri :: !String,
      accessToken :: Maybe Token,
      manager :: Manager,
      localDirectory :: String,
      authService :: String,
      authAccount :: String
    }

type Flow = ExceptT String (StateT OAuth2WebServerFlow IO)

