Compiling YAOG
===============

This describes openSSL & Yaog compilation on Windows x64 architecture.

Needed softwares
----------------

* Qt : Need version > 5.12.4 for openSSL 1.1.1 support
* Perl : https://www.activestate.com/ActivePerl
* Microsoft Visual C compiler : You can use MS VisualStudio 2017
* NASM : https://www.nasm.us

Paths
-----

Following paths are used : 
* NASM path `<NASM>` : main directory where you installed NASM
* OpenSSL path `<openssl>` : Where you decompressed OpenSSL source
* Yaog source path `<YAOG>` : Where you put the YAOG source
* Yaog binary path `<YAOG-Bin>` : Where Qt compiled Yaog

Compile OpenSSL
---------------

Get the source from openssl (https://www.openssl.org/source/) and untar in `<openssl>`

You can read 'NOTES.WIN' for compile targets / needed software / etc...

Launch "x64 Native Tools Command Prompt for VS 2017" 
 
* set path for NASM : `set PATH=%PATH%;<NASM>`
* Configure for Windows 64 target :  `perl Configure VC-WIN64A`
* Compile : `nmake`
* Check software is working : `nmake test`


Get Yaog source
---------------

With Git or download master (https://github.com/patrickpr/YAOG/archive/master.zip) 

Copy in `<YAOG>` directory.

Remove current openSSL includes : 
```
delete <YAOG>/src/openssl/lib/*
delete <YAOG>/src/openssl/include/openssl/*
```

Copy your OpenSSL version : 
```
copy <openssl>/include/openssl/* <YAOG>/src/openssl/include/openssl/

copy <openssl>/ms/applink.c <YAOG>/src/openssl/include/openssl/
```
In applink.c, line 104 to 127, force conversion to (void*) or there will be an error at compile time : 

Notepad++ regexp replace : `(.*) = (.*)  ->   \1 = \(void*\) \2`
```
copy <openssl>/libcrypto* <YAOG>/src/openssl/lib/
copy <openssl>/libssl* <YAOG>/src/openssl/lib/
```

Compile with Qt
---------------

Open project file 'YetAnotherOpensslGui.pro'

Create a target : Desktop Qt `<version>` MinGW 64-bit

Set target directory to `<YAOG-Bin>`

Compile project !

Include DLLs
------------

* Qt DLLs

In `<YAOG-Bin>` directory in CLI, run :

`C:\Qt\<version>\<platform>_<32_64>\bin\windeployqt.exe --release YetAnotherOpensslGui.exe`

* Add mingw DLL

From directory : `C:\Qt\Tools\mingw<version>_64\bin copy to <YAOG-Bin>` : 
** libgcc_s_seh-1.dll
** libstdc++-6.dll
** libwinpthread-1.dll
	
* Add compiled openssl DLL 

Copy to `<YAOG-Bin>` 

- `<openssl>/libcrypto-1_1-x64.dll`
- `<openssl>/libssl-1_1-x64.dll`
