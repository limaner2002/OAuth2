module Network.OAuth2.URI
    where

import Network.HTTP.Conduit

class URI a
    where
      render :: a -> String

      request :: a -> String
      request uri = render uri
