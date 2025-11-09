# Titre du projet
LinuxKeyrings


## Description
Wrapper functions for Linux kernel "keyrings" API
See "man 7 keyrings"
The kernel functionnality, not to be confused with other things names "keyring", like Gnome's, KDE's...

All functions are described in "man 2 keyctl"


### Data types mappings
C type  ->   java type
keyring_serial_t    ->  int
char* description   ->  String
char* type          ->  String
char* payload       ->  byte[]

Note that for "description" and "type", an UTF-8 decode/encode is done.
For "type", we do not expect to see non-ASCII chars, but it will simplify the use of String literals instead of byte[] literals

For payload, no coding is done.



### Java class
LinuxKeyrings is a static only class
It will not store any running data : key and keyrings are only described in you program using 'int' handle, the same type as the kernel does.


### Static class initialization
LinuxKeyrings must locate the LinuxKeyrings.so shared object at initialization.
See TODO 


## TODO
- use Java exceptions to handle errors
- Exhaustive testing of all functions
- Implement other functions
- Make a "soInit" method for loading the .so object. Thus the location can be given by the program, not requiring .so to be in /usr/lib or other standard location.



## Requirements
Written using :
- openjdk 21.0.8 2025-07-15
- gcc (Debian 14.2.0-19) 14.2.0


## Compilation and installation
```make
```
Then put LinuxKeyrings.class and LinuxKeyrings.so wherever you want


## Tests
TODO



## Licence
GNU AFFERO GENERAL PUBLIC LICENSE Version 3
See LICENSE.txt

