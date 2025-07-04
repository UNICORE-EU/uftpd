Changelog for the UFTPD server
==============================

[Issue tracker](https://github.com/UNICORE-EU/uftpd/issues)

[Full documentation](https://uftp-docs.readthedocs.io)

UFTPD 3.5.0 (released July 04, 2025)
-----------------------------------
 - new feature: enable dualstack IPv6/IPv4 support for command and ftp servcers,
   if the configured hostname supports it, and it is not explicitly disabled
   via "DISABLE_IPv6=true" in the uftpd.conf
 - improvement: use empty hostname ("") or hostname = "*" to bind on
   all interfaces
 - improvement: make some parameters settable via the FTP control channel
   (e.g. file read/write buffer size)
 - improvement: optionally use os.sendfile() for GET
 - fix: avoid error messages in log due to PAM close_session call
 - fix: use USER_NAME instead of USER in conf and start script
 - fix: MLST should return error code 550 if file does not exist
 - fix: don't follow symlinks when setting modification time
 - fix: the "persistent" flag for sessions was not implemented
 - fix: archive mode creates missing intermediate directories
 - fix: more consistent path handling and path comparisons
 - code cleanup

UFTPD 3.4.1 (released Apr 29, 2024)
-----------------------------------
 - fix: enable SO_KEEPALIVE on data connections as well
 - fix: UFTPD should still run on (old) Python 3.6.8
 - improvement: SSL ciphers can be configured in uftpd-ssl.conf variable "SSL_CIPHERS"
 - minor code cleanup

UFTPD 3.4.0 (released Mar 05, 2024)
-----------------------------------
 - new feature: report MaxSessionsPerClient setting to Auth server in "ping" reply
 - new feature: add PAM.py to optionally put UFTPD processes into the systemd user slice
 - new feature: AES encryption support
 - new feature: remote-copy supports compression, encryption and multiple TCP streams
 - fix: writing to existing files: only truncate when clients sends ALLO (no RANG/REST)
 - fix: check crypto support when starting
 - fix: multi-tcp-stream combined with encryption was not working correctly
 - do not accept transfers requesting crypted connections if crypto support is not available

UFTPD 3.3.0 (released Jun 30, 2023)
-----------------------------------
 - fix: set the byte range correctly in ALLO / STOR sequence
 - fix: create new message digest object for each HASH
 - improvement: report errors when adding new transfer request back to Auth server
 - new feature: support MFF command for setting file mode (e.g. "UNIX.mode=777") and modification time
 - improvement: MLST reply includes 'UNIX.mode' (octal chmod style, e.g. '10777')

UFTPD 3.2.0 (released Apr 17, 2023)
-----------------------------------
 - new feature: implement file sync SYNC-TO-CLIENT and SYNC-TO-SERVER
 - new feature: initial version of server-to-server transfer
 - fix: output of stat(".") in directory '/' was missing the path
 - fix: duplicate "530 Not logged in" response
 
UFTPD 3.1.3 (released Sep 20, 2022)
-----------------------------------
 - fix: server could hang when ACL contains typos
 - fix: ignore upper/lower case when parsing ACL and matching DNs
 - fix: cleaner handling of session's initial and base directories
 - fix: LIST reply is always "ls-style" for better interoperability with other FTP tools
 - fix: wrong syntax of MLST/MLSD response "facts" part
 - fix: log common name of connecting server when access is denied
 - fix: RPM/DEB should be architecture-independent

UFTPD 3.1.2 (released Dec 16, 2021)
-----------------------------------
 - improvement: support credential as separate key and certificate files
 - fix: reply for checksum of files with length zero gave "-1" as the last byte

UFTPD 3.1.1 (released Dec 8, 2021)
-----------------------------------
 - new feature: HASH command to get file checksums (#70)
 - fix: cleanup child processes forked in get_user_info()

UFTPD 3.1.0 (released Oct 27, 2021)
------------------------------------
 - improvement: allow to run as unprivileged user with added
   setuid/setgid capabilities via 'setpriv' or similar tool
 - fix: getting a file that exists but is not readable does
   not result in the right error message
 - fix: STOR without previous RANG command should truncate 
   the file before writing
 - fix: in a "restricted" session, check access permission using
   absolute paths of files

UFTPD 3.0.4 (released Sept 13, 2021)
------------------------------------
 - fix: ACL parsing for DNs with '/' (#66)
 - fix: UFTPD fails when user's home does not exist

UFTPD 3.0.3 (released July 2, 2021)
-----------------------------------
 - fix: writing file chunks was buggy
 
UFTPD 3.0.2 (released May 27, 2021)
-----------------------------------
 - fix: read user keys after privilege drop to avoid issues with root-squash filesystems
 - fix: implement rename (RNFR, RNTO)
 - fix: implement append (APPE) and writing to an existing file with offset

UFTPD 3.0.1 (released May 10, 2021)
----------------------------------
 - fix: accept and ignore empty lines on command channel
 - fix: implement MLSD command
 - fix: close existing / "forgotten" data connection when client opens a new one
 - fix: date format in MLST and MLSD replies

UFTPD 3.0.0 (released Apr 27, 2021)
----------------------------------
 - first release of the Python implementation
 - simpler execution model based on fork, every FTP session runs as a separate process
 - cleaner security (users/groups) and better control over file permissions
 - logs to syslog

KNOWN ISSUES:
 - removed SYNC command (for now)
 - uploading using both multiple TCP streams and compression is not working correctly
