About nxsmb:
============
nxsmb is a C++ multithreaded SMB2/3 server implementation.


Dependencies
------------
g++, heimdal-dev, libtdb-dev


Build Instructions
------------------

Copy 'winbind_struct_protocol.h' from samba to some directory, e.g., samba_nsswitch, please make sure 'winbind_struct_protocol.h' is the same version as winbindd

make TARGET_CFLAGS_platform=samba_nsswitch


Run nxsmb
----------
nxsmb requires samba winbindd service as well as the net util to join domain, you can
either build samba from source, or install package 'samba-common-bin' and 'winbind'.

1, create smb.conf
2, join domain, run command 'net ads join ...'
3, run winbindd
4, run the SMB server of nxsmb 'smbd-nx'



Contact
-------
If you have any question, feel free to contact me.  
Haihua Yang <yanghh@gmail.com>
