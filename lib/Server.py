#
# Helpers to create sockets
#

import errno
from os import stat
from time import time
import socket
import sys

from Connector import Connector
from Log import Logger
from SSL import setup_ssl, verify_peer, convert_dn

def configure_socket(sock: socket.socket):
    """
    Setup socket options (keepalive).
    """
    after_idle = 5
    interval = 1
    max_fails = 3
    sock.settimeout(None)
    if not sys.platform.startswith("win"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if sys.platform.startswith("darwin"):
        TCP_KEEPALIVE = 0x10
        sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, interval)
    if sys.platform.startswith("linux"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)


def close_quietly(closeable):
    try:
        closeable.close()
    except:
        pass

def update_acl(config: dict, LOG: Logger):
    last_checked = config.get("_last_acl_file_check", 0)
    now = int(time())
    if now < last_checked + 10:
        return
    acl_file = config.get('ACL')
    mtime = int(stat(acl_file).st_mtime)
    if last_checked >= mtime:
        return
    if last_checked > 0:
        LOG.info("ACL file '%s' modified - reloading entries." % acl_file)
    else:
        LOG.info("ACL file '%s'" % acl_file)
    config["_last_acl_file_check"] = now
    with open(acl_file, "r") as f:
        lines = f.readlines()
        acl = []
        config['uftpd.acl'] = acl
        for line in lines:
            try:
                line = line.strip()
                if line.startswith("#") or len(line)==0:
                    continue
                dn = convert_dn(line)
                LOG.info("Allowing access for <%s>" % line)
                acl.append(dn)
            except Exception as e:
                LOG.error("ACL entry '%s' could not be parsed: %s" % (line, e))

def setup_cmd_server_socket(config: dict, LOG: Logger) -> socket.socket:
    """
    Return command socket for communicating
    with the authentication server(s)

    Parameters: dictionary of config settings, logger
    """

    host = config['CMD_HOST']
    port = config['CMD_PORT']
    ssl_mode = config.get('SSL_CONF') is not None
    if ssl_mode:
        with open(config.get('SSL_CONF'), "r") as f:
            lines = f.readlines()
            for line in lines:
                try:
                    key, value = line.split("=",1)
                    config[key.strip()]=value.strip()
                except:
                    pass
        update_acl(config, LOG)
    addr = (host, port)
    fam = "IPv4"
    if _check_ipv6_support(host, port, config):
        fam = "IPv6/IPv4"
        server = socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True, reuse_port=True)
    else:
        server = socket.create_server(addr, reuse_port=True)
    if ssl_mode:
        server = setup_ssl(config, server, LOG, True)
    else:
        LOG.info("*****")
        LOG.info("*****   WARNING:")
        LOG.info("*****   Using a plain-text socket for receiving commands.")
        LOG.info("*****   On production systems you should enable SSL!")
        LOG.info("*****   Consult the UFTPD manual for details.")
        LOG.info("*****")
    LOG.info("UFTPD Command server socket (%s) started on %s:%s" % (fam, server.getsockname()[0], port))
    LOG.info("SSL enabled: %s" % ssl_mode)
    return server

def accept_command(server: socket.socket, config: dict, LOG: Logger) -> Connector:
    """ Waits for a connection from the Auth server. 
    Upon a new connection, it is checked it is from a valid source.
    If yes, the message is read and returned to the caller for processing.
    """
    ssl_mode = config.get('SSL_CONF') is not None

    server.listen(2)

    while True:
        try:
            (auth, peer_address) = server.accept()
        except EnvironmentError as e:
            if e.errno != errno.EINTR:
                LOG.error("Error waiting for new connection: " + str(e))
            continue

        if ssl_mode:
            try:
                update_acl(config, LOG)
                verify_peer(config, auth, LOG)
            except EnvironmentError as e:
                auth_host = "(n/a)"
                try:
                    auth_host = peer_address[0]
                except TypeError:
                    pass
                LOG.error("Error verifying connection from %s : %s" % (
                    auth_host, str(e)))
                close_quietly(auth)
                continue

        configure_socket(auth)
        connector = Connector(auth,LOG,conntype="COMMAND")
        LOG.debug("Accepted %s" % connector.info())
        return connector

    
def setup_ftp_server_socket(config: dict, LOG: Logger) -> socket.socket:
    """
    Return FTP listener socket

    Parameters: dictionary of config settings, logger
    """

    host = config['SERVER_HOST']
    port = config['SERVER_PORT']
    addr = (host, port)
    fam = "IPv4"
    if _check_ipv6_support(host,port,config):
        fam = "IPv6/IPv4"
        server = socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True, reuse_port=True)
    else:
        server = socket.create_server(addr, reuse_port=True)
    LOG.info("UFTPD Listener server socket (%s) started on %s:%s" % (fam, server.getsockname()[0], port))
    return server


def accept_ftp(server: socket.socket, LOG: Logger) -> Connector:
    """ Waits for a connection to the FTP socket
    """
    server.listen(2)

    while True:
        try:
            (client, _peer_addr) = server.accept()
        except EnvironmentError as e:
            if e.errno != errno.EINTR:
                LOG.error("Error waiting for new connection: " + str(e))
            continue

        configure_socket(client)
        return Connector(client,LOG)


def setup_data_server_socket(host, port_range=(0,-1,-1), enable_ipv6=True) -> socket.socket:
    """
    Return listener socket for data connections
    """
    port = port_range[0]
    use_port_range = port > 0
    if use_port_range:
        _lower = port_range[1]
        _upper = port_range[2]
        max_attempts = _upper-_lower+1
    else:
        max_attempts = 1
    attempts = 0
    while attempts<max_attempts:
        addr = (host, port)
        try:
            if enable_ipv6:
                return socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True, reuse_port=True)
            else:
                return socket.create_server(addr, reuse_port=True)
        except Exception as e:
            attempts+=1
            if use_port_range:
                port+=1
                if port>_upper:
                    port = _lower
            else:
                raise e
    raise Exception("Cannot set up data connection - no free ports in range %s:%s"% (_lower, _upper))

def accept_data(server: socket.socket, LOG: Logger, expected_client: str=None) -> Connector:
    """ Waits for a data connection
    """
    server.listen(2)
    attempts = 0
    while attempts < 3:
        try:
            (client, address) = server.accept()
            if expected_client is not None:
                client_host=address[0]
                if client_host!=expected_client:
                    raise Exception("Rejecting connection from unexpected host %s - expected %s" % (client_host, expected_client))
            configure_socket(client)
            return Connector(client, LOG, conntype="DATA", binary_mode=True)
        except EnvironmentError as e:
            LOG.error(e)
            attempts+=1

def _check_ipv6_support(host: str, port: int, config: dict) -> bool:
    enable_ipv6 = not config.get('DISABLE_IPv6', False)
    supports_ipv6 = len(host)==0 or host=="*"
    if supports_ipv6:
        return True
    for addrinfo in socket.getaddrinfo(host, port):
        if addrinfo[0]==socket.AF_INET6:
            supports_ipv6 = True
            break
    return enable_ipv6 and supports_ipv6