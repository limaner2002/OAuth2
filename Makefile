oauth2:
	ghc -o oauth2.dylib -dynamic -shared OAuth2.hs external/keychain.c

clean: 
	rm *.o *.hi *.dylib