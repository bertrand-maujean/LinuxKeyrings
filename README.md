# Titre du projet
LinuxKeyrings for java


## Description
Wrapper functions for Linux kernel "keyrings" API
The kernel functionnality, not to be confused with other things names "keyring", like Gnome's, KDE's...

All functions are described in :
- man 7 keyrings
- man 2 keyctl
- man 2 add_key
and so on

A part of the library is a C module, compiled as a shared object .so file.
This .so is loaded and used with JNI interface. See :
https://docs.oracle.com/en/java/javase/22/docs/specs/jni/


### Java class
LinuxKeyrings is a static only class.
It will not store any running data : key and keyrings are only described in you program using 'int' handle, the same type as the kernel does.
Important : sanitization of release memory after use is not garanteed (if needed : just code only in C/C++ !)


### Data types mappings
|C type              |  java type    |
|--------------------|---------------|
|keyring_serial_t    |  int          |
|char* description   |  String       | 
|char* type          |  String       |
|char* payload       |  byte[]       |

Note that for "description" and "type", an UTF-8 decode/encode is done.
For "type", we do not expect to see non-ASCII chars, but it will simplify the use of String literals instead of byte[] literals

For payload, no coding is done.

syscall use null-terminated bytes strings for description and type, and pointer/length for payload. In all cases, java types "String" and "byte[]" handle the length information without \0 or explicit length.

### Constants
Constants are provided as "public static final" for :
- builtin keyrings
- permissions bitmask


### Static class initialization
LinuxKeyrings must be informed of LinuxKeyrings.so shared object at initialization. One of the two methods must be call before any other :
- initLib(String libname) : will search in standard libraries path. libname must not contain "/" and end with ".so".  "lib" prefix will be adder (ld-linux behavior)
- initLibFilename(String filename) : provide a full file path, must be absolute beginning with "/" and end with ".so"

Standard exception can be thrown if library / filename is not found.

java.lang.UnsatisfiedLinkError is thrown by all methods if initialization is not done

Can the .so file be packaged in a jar ?
1/ no because it needs to be mmap()ed by the dynamic linker ld-linux
2/ yes there is a known trick using memfdcreate() then execve() on /proc/pid/fd
3/ no I didn't code it because I think it's not a good idea to add the constraint of having a visible /proc (think of light containers...)


### Exception / Error reporting
An anciliary class "ErrnoException" is provided to handle errors.
It deals with negative syscall return values
errnoGenCode.py was used one time to generate java const lists



## All methods :
### Wrappers methods are provided for :
```
248	sys_add_key	(const char *_type	const char *_description	const void *_payload	size_t plen		)
250	sys_keyctl ( * )
KEYCTL_GET_KEYRING_ID Map a special key ID to a real key ID for this process
KEYCTL_UPDATE         Update a key's data payload. 
KEYCTL_REVOKE         Revoke  the key with the ID provided 
KEYCTL_SETPERM        Change the permissions of the key with the ID provided 
KEYCTL_DESCRIBE       Obtain a string describing the attributes of a specified key. 
KEYCTL_CLEAR          Clear the contents 
KEYCTL_LINK           Create a link from a keyring to a key 
KEYCTL_UNLINK         Unlink a key from a keyring. 
KEYCTL_SEARCH         Search for a key in a keyring tree, returning its ID and optionally linking it to a specified keyring. 
KEYCTL_READ           Read the payload data of a key. 
KEYCTL_SET_TIMEOUT    Set a timeout on a key. 
KEYCTL_INVALIDATE     Mark a key as invalid. 
```

### Not provided :
```
KEYCTL_JOIN_SESSION_KEYRING Replace the session keyring this process subscribes to with a new session keyring.
KEYCTL_CHOWN                Change the ownership (user and group ID) of a key
KEYCTL_INSTANTIATE        (Positively) instantiate an uninstantiated key with a specified payload 
KEYCTL_NEGATE             Negatively instantiate an uninstantiated key. 
KEYCTL_SET_REQKEY_KEYRING Set the default keyring to which implicitly requested keys will be linked for this thread, and return the previous setting 
KEYCTL_ASSUME_AUTHORITY   Assume (or divest) the authority for the calling thread to instantiate a key. 
KEYCTL_GET_SECURITY       Get the LSM (Linux Security Module) security label of the specified key 
KEYCTL_SESSION_TO_PARENT  Replace the session keyring to which the parent of the calling process subscribes with the session keyring of the calling process. 
KEYCTL_REJECT             Mark a key as negatively instantiated and set an expiration timer on the key. 
KEYCTL_INSTANTIATE_IOV    Instantiate an uninstantiated key with a payload specified via a vector of buffers 
KEYCTL_GET_PERSISTENT     Get the persistent keyring (persistent-keyring(7)) for a specified user and link it to a specified keyring. 
KEYCTL_DH_COMPUTE         Compute a Diffie-Hellman shared secret or public key 
KEYCTL_RESTRICT_KEYRING   Apply  a key-linking restriction to the keyring  

249	sys_request_key	(const char *_type	const char *_description	const char *_callout_info	key_serial_t destringid		)
```

## TODO
- Exhaustive testing of all method, in error cases
- Implement request_key




## Requirements
Written using :
- openjdk 21.0.8 2025-07-15
- gcc (Debian 14.2.0-19) 14.2.0

The .so file has no dependancies. It's only a syscall wrapper, it don't even depend on a specific libc version. So it should be very portable.

libkeyutils.so is not used but keyutils.h is needed for build. For Debian Trixie, needed packages :
```
keyutils               Linux Key Management Utilities
libkeyutils-dev:amd64  Linux Key Management Utilities (development)
libkeyutils1:amd64     Linux Key Management Utilities (library)
```


## Compilation and installation
In the Makefile, adjust the CCFLAGS to the correct location for jni header files (somewhere in the JDK tree)
```
cd src/
make
```
Then put files in ../bin wherever you want.


## Tests
App.java provided
(adjust .so location, an absolute path is needed)


## Licence
GNU AFFERO GENERAL PUBLIC LICENSE Version 3
See LICENSE.txt

