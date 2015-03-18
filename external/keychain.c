#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>
#include <stdio.h>

int StorePasswordKeychain (void* serviceName, UInt32 serviceNameLength,
			   void* accountName, UInt32 accountNameLength,
			   void* password, UInt32 passwordLength
			   ){
  assert(passwordLength <= 0xffffffff);
  OSStatus status;
  status = SecKeychainAddGenericPassword (
  					  NULL,               // default keychain
  					  serviceNameLength,                 // length of service name
  					  serviceName,  // service name
  					  accountNameLength,                 // length of account name
  					  accountName,          // account name
  					  passwordLength,     // length of password
  					  password,           // pointer to password data
  					  NULL                // the item reference
  					  );
  return status;
}

//Call SecKeychainFindGenericPassword to get a password from the keychain:
char* GetPasswordKeychain (void* serviceName, UInt32 serviceNameLength,
			   void* accountName, UInt32 accountNameLength){
  OSStatus status ;
  SecKeychainItemRef itemRef = NULL;

  /* PwdStruct *result = malloc(sizeof(PwdStruct)); */
  UInt32 passwordLength;
  void *password;
 
  status = SecKeychainFindGenericPassword (
					   NULL,           // default keychain
					   serviceNameLength,             // length of service name
					   serviceName,   // service name
					   accountNameLength,             // length of account name
					   accountName,   // account name
					   &passwordLength,  // length of password
					   &password,   // pointer to password data
					   &itemRef         // the item reference
					   );

  char *result;
  if(status != noErr){
    result = NULL;
  }else{
    result = malloc(sizeof(char)*(passwordLength+1));
    memcpy(result, password, passwordLength);
    result[passwordLength] = '\0';
    status = SecKeychainItemFreeContent(
					NULL,
					password);
  }

  return result;
}

void ffree(char *ptr){
  printf("Freeing pointer at %p\n", ptr);
  free(ptr);
}
