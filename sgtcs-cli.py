#!/usr/bin/env python3
"""sgtcs-cli - Sectigo Terena Certificate Service command line interface

Usage:
  sgtcs-cli new [options] <hostname> [<althostname>...]
  sgtcs-cli retrieve [options] <hostname>
  sgtcs-cli list-types [options]

Options:
  -h --help              Show this screen
  --customer=<customer>  Sectigo customer name
  --username=<username>  Username
  --password=<password>  Password
  --subdir=<subdir>      Subdirectory to store files under
                         (default: current year)
  --type=<type>          profile of cert to request (match either id or name)
  --term=<term>          Validity period (days)
  --no-act               don't actually request/retrieve
"""

# by Dennis van Dok 
# Copyright Nikhef (NWO-I) 2020-2022
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from requests import Request, Session
from docopt import docopt
from time import time, localtime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from os import uname

myhostname = uname()[1]

# hardcoded orgid Nikhef for the moment
orgid = 11358

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
    typesdata = { 'organizationId': orgid }
    url = baseurl + 'ssl/v1/types'
    r = s.get(url, json=typesdata)
    if r.status_code != 200:
        dump_response(r)
        responsefail(r, 'Could not retrieve certificate profiles')
    return r.json()
    

def enroll(csrdata, certtype, term, hostname, altnames):
    newreqdata = {'orgId': orgid,
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
                  'comments': 'Requested via sgtcs-cli.py on ' + myhostname,
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
    newreqdata = {'orgId': orgid,
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
    print(r.json())

def pretty_print_types(types):
    """Print the retrieved certificate profile list"""
    for i in types:
        print('{}:\t{}\t{} (terms: {})'.format(
            i.get('id'),
            i.get('name'),
            i.get('description'),
            ','.join(str(n) for n in i.get('terms'))))

def fuzzy_match(t, types):
    """Find a matching type in the types list"""
    if t.isdigit():
        # Assume we match on id
        id = int(t)
        for i in types:
            if i['id'] == id:
                return i
        print('no match found for certificate profile {}'.format(id))
        print('Choose one from the list available below:')
        pretty_print_types(types)
        exit(1)
    else:
        lt = t.lower().replace('-', ' ')
        for i in types:
            name = i['name'].lower().replace('-', ' ')
            if lt in name:
                return i
        print('no fuzzy match found for certificate name {}'.format(lt))
        print('Choose one from the list available below:')
        pretty_print_types(types)
        exit(1)
            
        
current_year = localtime(time())[0]

        
# This is the list of types we can use. Let's make a static
# structure from it.
#[{'id': 8575, 'name': '01 GÉANT OV Multi-Domain', 'description': 'max 250 SubjAltNames; mogen ook wildcards zijn', 'terms': [365]},
# {'id': 8578, 'name': '03 GÉANT EV Multi-Domain', 'description': 'alleen aanvragen als je al een EV Anchor hebt', 'terms': [365]},
# {'id': 8582, 'name': '04 GÉANT IGTF Multi-Domain', 'description': "if you don't know what IGTF eScience Grid certificates are, then this is not for you", 'terms': [395]},
# {'id': 8586, 'name': '02 GÉANT Wildcard SSL', 'terms': [365]},
# {'id': 8589, 'name': '99 EV Anchor Certificate', 'description': "Nieuw in EV? Vraag scs-ra@surfnet.nl om de 'EV details' voor je org in te voeren voor je een Anchor aanvraagt", 'terms': [395]},
# {'id': 15225, 'name': 'david-test-profile', 'terms': [395]},
# {'id': 15452, 'name': '50 Sectigo RSA with SHA-256', 'description': 'EliteSSL, de oude combinatie van RSA met SHA-256; geen SubjAltNames; alleen 1 Common Name', 'terms': [365]}]

#try:
#    url = baseurl + 'organization/v1'
#    r = s.get(url)
#    print(r.request.headers)
#    print('body:')
#    print(r.request.body)
#    print(r.headers)
#    print(r.status_code)
#    print(r.json())
#
#    url = baseurl + 'ssl/v1/enroll'
#    r = s.post(url, json=newreqdata)
#
#    print(r.request.headers)
#    print('body:')
#    print(r.request.body)
#    print(r.headers)
#    print(r.status_code)
#    print(r.json())
#except Exception as exc:
#    print(exc)

def responsefail(r,msg):
    print("{}: {} {}".format(msg, r.status_code, r.json().get("description")))
    exit(2)
    
if __name__ == '__main__':
    arguments = docopt(__doc__, version='sgtcs-cli 0.2')
    #print(arguments)

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

subdir = arguments['--subdir']
if subdir is None:
    subdir = current_year

noact = arguments['--no-act']

if noact:
    print("--no-act flag given: not actually generating requests")
    
if arguments['list-types']:
    certtypes = get_types()
    pretty_print_types(certtypes)
    #dump_response(r)
elif arguments['new']:
    certtypes = get_types()
    tp = arguments['--type']
    if tp is None:
        tp = 'igtf'

    # find a match for the requested type by some fuzzy algorithm
    certtype = fuzzy_match(tp, certtypes)

    # Put in an explicit block on EV types
    if 'EV' in certtype['name']:
        print('Requesting EV certificates via this software is disabled')
        exit(1)

    if arguments['--term'] is not None:
        term = arguments['--term']
    else:
        term = certtype['terms'][0]
        
    print('certtype: %s' % certtype)
    print('term: %d' % term)
    # enroll a new certificate
    hostname = arguments['<hostname>']
    storagepath = "{}/{}".format(hostname, subdir)

    if not os.path.isdir(hostname):
        if os.path.exists(hostname):
            print("file {} is in the way and not a directory. Move it or remove it.")
            exit(1)
        os.mkdir(hostname, mode=0o755)
    
    try:
        os.mkdir(storagepath, mode=0o755)
    except FileExistsError as e:
        print("could not create directory {}: {}".format(storagepath, e))
        exit(2)

    keypath = storagepath + '/hostkey.pem'
    csrpath = storagepath + '/hostreq.pem'
    # create a new key
    key = generate_key()
    write_key_to_file(key, keypath)
    # generate a csr
    althostnames = arguments['<althostname>']
    csr = generate_csr(key, hostname, althostnames)
    csrdata = write_csr_to_file(csr, csrpath)
    # submit the csr
    if not noact:
        r = enroll(csrdata, certtype['id'], term, hostname, althostnames)
        #dump_response(r)
        print(r.json())
        j = r.json()
        #r = enroll_keygen(certtype, hostname)
        # if successful, write the request id out to a file for retrieval later
        #{"renewId":"SdibUBp-loQxlarC3XWr","sslId":1757496}
        with open(storagepath + '/requestid.txt', 'w') as f:
            f.write(str(j['sslId']))
        print('Request submitted, request id stored in {}/requestid.txt'.format(storagepath))

elif arguments['retrieve']:
    hostname = arguments['<hostname>']
    storagepath = "{}/{}".format(hostname, subdir)
    with open(storagepath + '/requestid.txt', 'r') as f:
        sslid = f.read().rstrip()
    if not noact:
        r = retrieve(hostname, sslid)
        with open(storagepath + '/hostcert.pem', 'w') as f:
            f.write(r.content.decode(r.encoding))
        print('Retrieved {}/hostcert.pem'.format(storagepath))
