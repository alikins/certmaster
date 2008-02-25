"""
Copyright 2007-2008, Red Hat, Inc
see AUTHORS

This software may be freely redistributed under the terms of the GNU
general public license.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
"""

import os
import string
import sys
import traceback
import xmlrpclib
import socket
import time
import glob

import codes
import certs
from config import read_config
from commonconfig import MinionConfig
import logger

# FIXME: module needs better pydoc


# FIXME: can remove this constant?
REMOTE_ERROR = "REMOTE_ERROR"


def trace_me():
    x = traceback.extract_stack()
    bar = string.join(traceback.format_list(x))
    return bar

def daemonize(pidfile=None):
    """
    Daemonize this process with the UNIX double-fork trick.
    Writes the new PID to the provided file name if not None.
    """

    print pidfile
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.setsid()
    os.umask(0)
    pid = os.fork()

    if pid > 0:
        if pidfile is not None:
            open(pidfile, "w").write(str(pid))
        sys.exit(0)

def nice_exception(etype, evalue, etb):
    # FIXME: I believe we can remove this function
    etype = str(etype)
    lefti = etype.index("'") + 1
    righti = etype.rindex("'")
    nicetype = etype[lefti:righti]
    nicestack = string.join(traceback.format_list(traceback.extract_tb(etb)))
    return [ REMOTE_ERROR, nicetype, str(evalue), nicestack ] 

def is_error(result):
    # FIXME: I believe we can remove this function
    if type(result) != list:
        return False
    if len(result) == 0:
        return False
    if result[0] == REMOTE_ERROR:
        return True
    return False

def get_hostname(talk_to_certmaster=True):
    """
    "localhost" is a lame hostname to use for a key, so try to get
    a more meaningful hostname. We do this by connecting to the certmaster
    and seeing what interface/ip it uses to make that connection, and looking
    up the hostname for that. 
    """
    # FIXME: this code ignores http proxies (which granted, we don't
    #      support elsewhere either. It also hardcodes the port number
    #      for the certmaster for now
    hostname = None
    hostname = socket.gethostname()
    # print "DEBUG: HOSTNAME TRY1: %s" % hostname
    try:
        ip = socket.gethostbyname(hostname)
        # print "DEBUG: IP TRY2: %s" % ip
    except:
        # print "DEBUG: ERROR: returning"
        return hostname
    if ip != "127.0.0.1":
        # print "DEBUG: ERROR: returning 2"
        return hostname

    if talk_to_certmaster:
        config_file = '/etc/certmaster/minion.conf'
        config = read_config(config_file, MinionConfig)

        server = config.certmaster
        port = 51235

        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((server, port))
            (intf, port) = s.getsockname()
            remote_hostname = socket.gethostbyaddr(intf)[0]
            if remote_hostname != "localhost":
               hostname = remote_hostname
               # print "DEBUG: HOSTNAME FROM CERTMASTER == %s" % hostname
            s.close()
        except:
            s.close()
            raise

    # print "DEBUG: final hostname=%s" % hostname
    return hostname
    

# FIXME: move to requestor module and also create a verbose mode
# prints to the screen for usage by /usr/bin/certmaster-request

def create_minion_keys():
    # FIXME: paths should not be hard coded here, move to settings universally
    config_file = '/etc/certmaster/minion.conf'
    config = read_config(config_file, MinionConfig)
    cert_dir = config.cert_dir
    master_uri = 'http://%s:51235/' % config.certmaster
    # print "DEBUG: acquiring hostname"
    hn = get_hostname()
    # print "DEBUG: hostname = %s\n" % hn

    if hn is None:
        raise codes.CMException("Could not determine a hostname other than localhost")

    key_file = '%s/%s.pem' % (cert_dir, hn)
    csr_file = '%s/%s.csr' % (cert_dir, hn)
    cert_file = '%s/%s.cert' % (cert_dir, hn)
    ca_cert_file = '%s/ca.cert' % cert_dir


    if os.path.exists(cert_file) and os.path.exists(ca_cert_file):
        # print "DEBUG: err, no cert_file"
        return

    keypair = None
    try:
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
        if not os.path.exists(key_file):
            keypair = certs.make_keypair(dest=key_file)
        if not os.path.exists(csr_file):
            if not keypair:
                keypair = certs.retrieve_key_from_file(key_file)
            csr = certs.make_csr(keypair, dest=csr_file)
    except Exception, e:
        traceback.print_exc()
        raise codes.CMException, "Could not create local keypair or csr for session"

    result = False
    log = logger.Logger().logger
    while not result:
        try:
            # print "DEBUG: submitting CSR to certmaster: %s" % master_uri
            log.debug("submitting CSR to certmaster %s" % master_uri)
            result, cert_string, ca_cert_string = submit_csr_to_master(csr_file, master_uri)
        except socket.gaierror, e:
            raise codes.CMException, "Could not locate certmaster at %s" % master_uri

        # logging here would be nice
        if not result:
            # print "DEBUG: no response from certmaster, sleeping 10 seconds"
            log.warning("no response from certmaster %s, sleeping 10 seconds" % master_uri)
            time.sleep(10)


    if result:
        # print "DEBUG: recieved certificate from certmaster"
        log.debug("received certificate from certmaster %s, storing" % master_uri)
        cert_fd = os.open(cert_file, os.O_RDWR|os.O_CREAT, 0644)
        os.write(cert_fd, cert_string)
        os.close(cert_fd)

        ca_cert_fd = os.open(ca_cert_file, os.O_RDWR|os.O_CREAT, 0644)
        os.write(ca_cert_fd, ca_cert_string)
        os.close(ca_cert_fd)

def submit_csr_to_master(csr_file, master_uri):
    """"
    gets us our cert back from the certmaster.wait_for_cert() method
    takes csr_file as path location and master_uri
    returns Bool, str(cert), str(ca_cert)
    """

    fo = open(csr_file)
    csr = fo.read()
    s = xmlrpclib.ServerProxy(master_uri)

    # print "DEBUG: waiting for cert"
    return s.wait_for_cert(csr)
              
