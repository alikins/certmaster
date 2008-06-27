# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# Copyright (c) 2007 Red Hat, inc 
#- Written by Seth Vidal skvidal @ fedoraproject.org

from OpenSSL import crypto
import socket
import os
import utils
import random
import sys

def make_keypair(dest=None):
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)
    if dest:
        destfd = os.open(dest, os.O_RDWR|os.O_CREAT, 0600)
        os.write(destfd, (crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)))
        os.close(destfd)
    
    return pkey


def make_csr(pkey, dest=None, cn=None):
    req = crypto.X509Req()
    req.get_subject()
    subj  = req.get_subject()

    if cn:
        subj.CN = cn
    else:
        subj.CN = utils.get_hostname() 
    subj.emailAddress = 'root@%s' % subj.CN       
        
    req.set_pubkey(pkey)
    req.sign(pkey, 'md5')
    if dest:
        destfd = os.open(dest, os.O_RDWR|os.O_CREAT, 0644)
        os.write(destfd, crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))
        os.close(destfd)

    return req


def retrieve_key_from_file(keyfile):
    fo = open(keyfile, 'r')
    buf = fo.read()
    keypair = crypto.load_privatekey(crypto.FILETYPE_PEM, buf)
    return keypair

    
def retrieve_csr_from_file(csrfile):
    fo = open(csrfile, 'r')
    buf = fo.read()
    csrreq = crypto.load_certificate_request(crypto.FILETYPE_PEM, buf)
    return csrreq


def retrieve_cert_from_file(certfile):
    fo = open(certfile, 'r')
    buf = fo.read()
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, buf)
    return cert


def create_extensions(extensions):
    xextlist = []
    for name, critical, value in extensions:
        print name, critical, value
        xext = crypto.X509Extension(name, critical, value)
        xextlist.append(xext)

    return xextlist

def create_ca_extensions():
    extensions = [
        ("nsCertType", 0, "objsign"),
        ("basicConstraints", 1, "CA:TRUE")
        ]

    return create_extensions(extensions)

def create_slave_extensions():
    extensions = [
        ("nsCertType", 0, "client,server"),
        ("basicConstraints", 1, "CA:FALSE")
        ]

    return create_extensions(extensions)


def create_ca(CN="Certmaster Certificate Authority", ca_key_file=None, ca_cert_file=None, ca_dir=None):
    cakey = make_keypair(dest=ca_key_file)
    careq = make_csr(cakey, cn=CN)
    cacert = crypto.X509()


    cacert.gmtime_adj_notBefore(0)
    cacert.gmtime_adj_notAfter(60*60*24*365*10) # 10 yrs - hard to beat this kind of cert!
    cacert.set_issuer(careq.get_subject())
    cacert.set_subject(careq.get_subject())
    cacert.set_serial_number(_get_serial_number(ca_dir))
    cacert.set_pubkey(careq.get_pubkey())
#    cacert.add_extensions(create_ca_extensions())
    cacert.sign(cakey, 'sha1')
    if ca_cert_file:
        destfo = open(ca_cert_file, 'w')
        destfo.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cacert))
        destfo.close()
 
                                           
def _get_serial_number(cadir):
    serial = '%s/serial.txt' % cadir

    # we start with a random number, and increment it from there
    # to give us plenty of room, we start somewhere between 0 and maxint/2
    # why? issuer+serial number needs to be unique, for revocation
    
    i = random.randint(0, (sys.maxint/2))
    print i, serial
    if os.path.exists(serial):
        f = open(serial, 'r').read()
        f = f.replace('\n','')
        try:
            i = int(f)
            i+=1      
        except ValueError, e:
            i = 1

    print "i", i
    _set_serial_number(cadir, i)        
    return i


def _set_serial_number(cadir, last):
    serial = '%s/serial.txt' % cadir
    f = open(serial, 'w')
    f.write(str(last) + '\n')
    f.close()
            
        
def create_slave_certificate(csr, cakey, cacert, cadir, slave_cert_file=None):
    cert = crypto.X509()
    cert.set_serial_number(_get_serial_number(cadir))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60*60*24*365*10) # 10 yrs - hard to beat this kind of cert!
    cert.set_issuer(cacert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
#    cert.add_extensions(create_slave_extensions())
    cert.sign(cakey, 'md5')
    if slave_cert_file:
        destfo = open(slave_cert_file, 'w')
        destfo.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        destfo.close()
    return cert
