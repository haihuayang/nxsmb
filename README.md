About nxsmb:
============
nxsmb is a C++ multithreaded SMB2/3 server implementation.


Dependencies
------------
g++, heimdal-devel, libtdb-devel, openssl-devel, libuuid-devel, libattr-devel, jemalloc-devel, samba


Build Instructions
------------------

On Rocky Linux 8.10 (currently only tested on this platform):
1. install dependencies
```
   sudo dnf install -y epel-release
   sudo dnf install -y gcc-toolset-13-gcc-c++ python3 make
   sudo dnf install -y heimdal-devel libtdb-devel openssl-devel libuuid-devel libattr-devel jemalloc-devel
```
3. enable gcc-toolset-13, e.g,
```
   source /opt/rh/gcc-toolset-13/enable
```
5. download samba source code, nxsmb internally communicate with samba winbindd service, so please
checkout the same version as your samba installation, e.g.,
```
   git clone https://git.samba.org/samba.git && cd samba && git checkout v4-19-stable 
```
5. build nxsmb
```
   make TARGET_CFLAGS_platform=-I<samba-dir>/nsswitch PLATFORM=linux
```

Run nxsmb
----------
nxsmb requires samba winbindd service as well as the net util to join domain, you can
either build samba from source, or install package 'samba-common-bin' and 'winbind'.

1. modify /etc/samba/smb.conf to include the following lines:
```
[global]
security = ADS
workgroup = YOUR_DOMAIN
realm = YOUR_REALM
netbios name = YOUR_SERVER_NAME
winbind use default domain = yes
winbind enum users = yes
winbind enum groups = yes
```

2. join domain
```
   sudo net ads join ...
```
4. start winbindd service
```
   sudo systemctl start winbind
```
5. create directory for nxsmb, e.g.,
```
   sudo mkdir -p /var/log/nxsmb /etc/nxsmb
```

6. create shares directory, e.g.,
```
   sudo mkdir -p /home/nxsmb/shares/SMBBasic
   sudo ./dbg.linux.x86_64/nxutils init-volume /home/nxsmb/shares/SMBBasic
```

8. create /etc/nxsmb/smbd.conf, e.g.,
```
log level = SMB:DBG
realm = YOUR_REALM
netbios name = YOUR_SERVER_NAME
workgroup = YOUR_DOMAIN
interfaces = ens3
log name = /var/log/nxsmb/smbd.log
log file size = 8M

durable log max record = 16

my:max opens = 20000
my:winbindd connection count = 10

my:samba lib dir = /var/lib/samba

# volume map format
# uuid:volume-id(0-65535):node-name:path
my:volume map = \
        85d49bcb-7c14-404b-b11a-ffe207732329:4100:YOUR_SERVER_NAME:/home/nxsmb/shares/SMBBasic

[SMBBasic]
my:uuid = d3115fc0-d376-4783-b9df-517a57a28968
my:volumes = 85d49bcb-7c14-404b-b11a-ffe207732329
```

7. start smbd_nx
   sudo ./dbg.linux.x86_64/bin/smbd_nx -c /etc/nxsmb/smbd.conf



Contact
-------
If you have any question, feel free to contact me.  
Haihua Yang <yanghh@gmail.com>
