import os
import threading

from Log import Logger
import BecomeUser, Connector, PAM, Protocol, Server, Session

def create_session(connector: Connector.Connector, config: dict, LOG: Logger, ftp_server, cmd_server):
    try:
        LOG.debug("Processing %s" % connector.info())
        job = Protocol.establish_connection(connector, config)
        if job is False:
            connector.close()
            return
        if job is None:
            connector.write_message("530 Not logged in: no matching transfer request found")
            connector.close()
            return
        if not config['DISABLE_IP_CHECK']:
            client_ips = job['client-ip'].split(",")
            peer = connector.client_ip()
            verified = False
            for client_ip in client_ips:
                if client_ip==peer:
                    verified=True
                    break
            if not verified:
                raise Exception("Rejecting connection for '%s' from %s, allowed: %s" % (job['user'], peer, str(client_ips)))
        job['SERVER_HOST'] = connector.my_ip()
        LOG.info("Established %s for '%s'" % (connector.info(), job['user']))
    except Exception as e:
        connector.write_message("500 Error establishing connection: %s" % str(e))
        connector.close()
        return
    
    limit = config['MAX_CONNECTIONS']
    user = job['user']
    user_job_counts = config['_JOB_COUNTER']
    counter = user_job_counts.get(user)
    with job['_LOCK']:
        if len(job['_PIDS'])>0:
            if not job["_PERSISTENT"]:
                connector.write_message("500 Session for these credentials is already running")
                connector.close()
                return
            num = counter.increment()
            if num>limit:
                counter.decrement()
                connector.write_message("500 Too many active transfer requests / sessions for '%s' - server limit is %s" % (user, limit))
                connector.close()
                return
    pid = os.fork()
    if pid:
        # parent
        connector.cleanup()
        LOG.debug("Created new UFTP session for '%s', child process <%s>" % (user, pid))
        with job['_LOCK']:
            job['_PIDS'].append(pid)
        return

    #
    # child - cleanup, drop privileges and launch session processing
    #
    pam_enabled = config.get('OPEN_USER_SESSIONS', False)
    pam_module = config.get('PAM_MODULE', PAM.PAM_MODULE)
    try:
        LOG.reinit()
        ftp_server.close()
        cmd_server.close()
        user = job['user']
        groups = job.get('group')
        if pam_enabled:
            pam_session = PAM.PAM(LOG, module_name=pam_module)
            pam_session.open_session(user)
        user_switch_status = BecomeUser.become_user(user, groups, config, LOG)
        if user_switch_status is not True:
            connector.write_message("530 Not logged in: %s" % user_switch_status)
            raise Exception("Cannot switch UID/GID: %s" % user_switch_status)
        connector.write_message("230 Login successful")
        job['UFTP_NOWRITE'] = config["UFTP_NOWRITE"]
        job['MAX_STREAMS'] = config['MAX_STREAMS']
        job['compress'] = job.get("compress", "false").lower()=="true"
        job['PORTRANGE'] = config.get("PORTRANGE", (0, -1, -1))
        job['ADVERTISE_HOST'] = config.get("ADVERTISE_HOST", None)
        session = Session.Session(connector, job, LOG)
        session.run()
        connector.close()
    except Exception as e:
        LOG.error(e)
    if pam_enabled:
        pam_session.close_session()
    os._exit(0)

def ftp_listener(ftp_server, config: dict, LOG: Logger, cmd_server):
    LOG.info("Started FTP listener thread.")
    while True:
        try:
            connector = Server.accept_ftp(ftp_server, LOG)
            worker_thread = threading.Thread(target=create_session,
                                  args=(connector, config, LOG, ftp_server, cmd_server))
            worker_thread.start()
        except Exception as e:
            LOG.error(e)
            try:
                connector.close()
            except:
                pass
