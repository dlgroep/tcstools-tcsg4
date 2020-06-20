#!/usr/bin/env python3
"""sgtcs-cli - Sectigo Terena Certificate Service command line interface

Usage:
  sgtcs-cli new [options] <hostname> [<althostname>...]
  sgtcs-cli retrieve [options] <hostname>
  sgtcs-cli list-types [options]

Options:
  -h --help              Show this screen
  --product=<product>    Select alternative certificate type
  --customer=<customer>  Sectigo customer name
  --username=<username>  Username
  --password=<password>  Password
  --type=( unified-comm | ov-multi-domain | ev-ssl
           | ev-multi-domain | igtf-multi-domain
           | wildcard-ssl | ov-ssl )
  --term=<term>          Validity period (days)

"""

# @(#)$Id$
# written by Dennis van Dok, Nikhef
#
# Prerequisites: python3, and "pip3 install cryptography"

import os
from requests import Request, Session
from docopt import docopt

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def generate_key():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return key

def write_key_to_file(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
def generate_csr(key, hostname, altnames):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u"org"),
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u"terena"),
        x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u"tcs"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"NL"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Amsterdam"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Nikhef"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        #x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"grid.sysadmin@nikhef.nl"),
    ])).add_extension(
        x509.SubjectAlternativeName(
            # Describe what sites we want this certificate for.
            [ x509.DNSName(x) for x in [hostname] + altnames ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=False,
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True,content_commitment=True,
                      data_encipherment=False, key_agreement=False, key_cert_sign=False,
                      crl_sign=False, encipher_only=False, decipher_only=False), critical=False
    # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256(), default_backend())
    return csr

def write_csr_to_file(csr, path):
    csrdata = csr.public_bytes(serialization.Encoding.PEM)
    with open(path, "wb") as f:
        f.write(csrdata)
    return csrdata.decode('ascii')

def get_types():
    typesdata = { 'organizationId': 11358 }
    url = baseurl + 'ssl/v1/types'
    r = s.get(url, json=typesdata)
    return r
    

def enroll(csrdata, certtype, term, hostname, altnames):
    newreqdata = {'orgId': 11358,
                  'csr': csrdata.rstrip(),
                  'subjAltNames': ','.join([hostname] + altnames),
                  'certType': certtype,
                  'numberServers': 1,
                  'serverType': -1, # no idea
                  'term': term,
                  'optionalFields': [{'name':'localityName','value':'Amsterdam'},
                                     {'name':'postalCode','value':''},
                                     {'name':'stateOrProvinceName','value':''},
                  ],
                  'comments': 'Requested via ' + __name__,
                  'externalRequester': '',
    }
    #data = {
    #    "orgId": org_id, "csr": csr.rstrip(), "subjAltNames": subject_alt_names, "certType": type_id,
    #    "numberServers": 1, "serverType": -1, "term": term, "comments": "Enrolled by %s" % self._client.user_agent,
    #    "externalRequester": ""
    #}
    
    url = baseurl + 'ssl/v1/enroll'
    r = s.post(url, json=newreqdata)
    return r

def retrieve(hostname, sslid):
    url = baseurl + 'ssl/v1/collect/{}/x509CO'.format(sslid)
    print(url)
    r = s.get(url)
    return r


def enroll_keygen(certtype, hostname):
    newreqdata = {'orgId': 11358,
                  'commonName': hostname,
                  'subjAltNames': hostname,
                  'certType': certtype,
                  'serverType': -1, # no idea
                  'term': 365,
                  'comments': 'Testing the API',
                  'algorithm': 'RSA',
                  'keySize': 2048,
                  'passPhrase': 'FooBar12',
    }
    url = baseurl + 'ssl/v1/enroll-keygen'
    r = s.post(url, json=newreqdata)
    return r
    
def dump_response(r):
    """Print the result of an API call response"""
    print(r.request.headers)
    print('body:')
    print(r.request.body)
    print(r.headers)
    print(r.status_code)
    #print(r.json())

# This is the list of types we can use. Let's make a static
# structure from it.
# which needs to be updated for SCM 20.5+
# [{'id': 425, 'name': 'GÉANT Unified Communications Certificate',
# 'terms': [365, 730]}, {'id': 426, 'name': 'GÉANT OV Multi-Domain',
# 'terms': [365, 730]}, {'id': 427, 'name': 'GÉANT EV SSL', 'terms':
# [365, 730]}, {'id': 428, 'name': 'GÉANT EV Multi-Domain', 'terms':
# [365, 730]}, {'id': 429, 'name': 'GÉANT IGTF Multi Domain', 'terms':
# [365, 395]}, {'id': 424, 'name': 'GÉANT Wildcard SSL', 'terms':
# [365, 730]}, {'id': 423, 'name': 'GÉANT OV SSL', 'terms': [365,
# 730]}]
certtypes = { 'unified-comm': 425,
              'ov-multi-domain': 426,
              'ev-ssl': 427,
              'ev-multi-domain': 428,
              'igtf-multi-domain': 429,
              'wildcard-ssl': 424,
              'ov-ssl': 423,
}
    

if __name__ == '__main__':
    arguments = docopt(__doc__, version='sectman 0.1')
    print(arguments)

# If no password is passed in, this environment variable should have the password
pw = arguments['--password']
if pw is None:
    pw = os.getenv('TCSAPIKEY')

username = arguments['--username']
if username is None:
    username = os.getenv('TCSAPIUSER')

# This is the base of Sectigo's REST API service
baseurl = 'https://cert-manager.com/api/'

s = Session()
s.headers.update({'customerUri': 'surfnet', 'login': username, 'password': pw})

if arguments['list-types']:
    r = get_types()
    dump_response(r)
elif arguments['new']:
    if arguments['--type'] is not None:
        certtype = certtypes[arguments['--type']]
    else:
        certtype = certtypes['igtf-multi-domain']
    if arguments['--term'] is not None:
        term = arguments['--term']
    else:
        term = 365
    print('certtype: %s' % certtype)
    # enroll a new certificate
    hostname = arguments['<hostname>']
    os.mkdir(hostname, mode=0o755)
    keypath = hostname + '/hostkey.pem'
    csrpath = hostname + '/hostreq.pem'
    # create a new key
    key = generate_key()
    write_key_to_file(key, keypath)
    # generate a csr
    althostnames = arguments['<althostname>']
    csr = generate_csr(key, hostname, althostnames)
    csrdata = write_csr_to_file(csr, csrpath)
    # submit the csr
    r = enroll(csrdata, certtype, term, hostname, althostnames)
    dump_response(r)
    print(r.json())
    j = r.json()
    #r = enroll_keygen(certtype, hostname)
    # if successful, write the request id out to a file for retrieval later
    #{"renewId":"RANDOM_TOKEN_FROM_SECTIGO","sslId":6666666}
    with open(hostname + '/requestid.txt', 'w') as f:
        f.write(str(j['sslId']))

elif arguments['retrieve']:
    hostname = arguments['<hostname>']
    with open(hostname + '/requestid.txt', 'r') as f:
        sslid = f.read().rstrip()
    r = retrieve(hostname, sslid)
    dump_response(r)
    with open(hostname + '/hostcert.pem', 'w') as f:
        f.write(r.content.decode(r.encoding))

