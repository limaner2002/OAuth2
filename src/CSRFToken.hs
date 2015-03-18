module CSRFToken
    where

-- import URI

data CSRFToken = CSRFToken
    { clientId :: !String,
      state :: !String,
      applicationName :: !String
    }

instance Show CSRFToken
    where
      show token = "clientId: "++clientId token
                   ++"\nstate: "++state token
                   ++"\nApplication Name: "++applicationName token

-- instance URI CSRFToken
--     where
--       render token = clientId token
--                    ++state token
--                    ++applicationName token