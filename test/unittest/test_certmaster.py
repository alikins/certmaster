#!/usr/bin/python


# unit test for certmaster

import unittest

from certmaster import certs


class BaseTest:
    def __init__(self):
        pass


class TestCa(BaseTest):
    def __init__(self):
        self.test_dir = "/tmp/test_certs"
        
        self.ca_key_file = "%s/test.key" % self.test_dir
        self.ca_cert_file = "%s/test.crt" % self.test_dir
        self.CN = "Test-Cert-CN"
        
    def test_create_ca(self):
        certs.create_ca(self.CN, self.ca_key_file, self.ca_cert_file, self.test_dir)


    def test_create_slave(self):
        pkey = certs.make_keypair("%s/test.pkey" % self.test_dir)
        csr = certs.make_csr(pkey, "%s/test.csr" % self.test_dir)
        certs.create_ca(self.CN, self.ca_key_file, self.ca_cert_file, self.test_dir)
        ca_cert = certs.retrieve_cert_from_file(self.ca_cert_file)
        ca_key = certs.retrieve_key_from_file(self.ca_key_file)
        certs.create_slave_certificate(csr, ca_key, ca_cert,
                                       self.test_dir, "%s/test_signed.crt" % self.test_dir)

