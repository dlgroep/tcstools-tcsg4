#! /bin/sh
#
# @(#)$Id$
#
#
# Copyright 2020 David Groep, Nikhef, Amsterdam
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
#

bits=4096
key=rsa
force=0

# ############################################################################
# usage help and instructions
#
help() { cat <<EOF
Usage: tcsg4-request.sh [-d destdir] hostname [hostname ...]

   -d destdir   write result files to <destdir>
                (default: ./tcs-<hostname>/)
   -b bits      use <bits> for RSA key length (default: 4096) or curve for 
                ECC (e.g. "prime256v1", set explicitly)
   -f | --force overwrite existing files
   -E | --ecc   generate ECC cert (remember to set -b to the curve!)

   hostname     hostname (FQDN) to be included in the request
                Any literal string "WILDCARD" will be replaced by
                a "*" in the hostname - it should ONLY be included as
                the first element of the fqdn, and MUST be on its own
     (the list of hostnames may be separated by spaces or commas)

EOF
   return;
}

# ############################################################################
#
while [ $# -gt 0 ]; do
case "$1" in
-b | --bits )              bits="$2"; shift 2 ;;
-E | --ecc )               key="ecc"; shift ;;
-f | --force )             force=1; shift ;;
-d | --destination )       destdir="$2"; shift 2 ;;
-* )                       echo "Unknown option $1, exiting" >&2 ; exit 1 ;;
*  )                       break ;;
esac
done

case "$#" in
0 ) help
    exit 1 
    ;;
* ) break ;;
esac

hn=`echo $1 | sed -e 's/[,\ ]//g;s/DNS://;'`
domain=$hn

case "$domain" in
[a-zA-Z][-a-zA-Z0-9\.][-a-zA-Z0-9\.]* ) ;;
*   ) echo "Invalid domain name '$domain', exiting." >&2 ; exit 1 ;;
esac

destdir="${destdir:-tcs-$domain}"

echo "Creating request for $domain in $destdir"

if [ -d "$destdir" -a $force -eq 0 ]; then
  echo "Directory $destdir for $domain already exists, exiting." >&2
  echo "use --force to override" >&2
  exit 1
fi

alt=""
while [ x"$1" != x"" ] ; do
  if [ x"$alt" != x"" ]; then
    alt="$alt,"
  fi
  hn=`echo $1 | sed -e 's/[,\ ]//g;s/DNS://;'`
  alt="${alt}DNS:$hn"
  shift
done

filebase="$domain"

domain=`echo $domain | sed -e 's/WILDCARD/\*/g'`
alt=`echo $alt | sed -e 's/WILDCARD/\*/g'`

echo "----------------------------------------------------------------------"
echo "Requesting certificate for $domain in $destdir"
echo " SAN dNSNames: $alt"

fn=`mktemp /tmp/request.cnf.XXXXXX`

cat <<EOF > $fn
[ req ]
default_bits            = 0
default_keyfile         = $destdir/key-$filebase.pem
distinguished_name      = req_distinguished_name
attributes              = req_attributes
prompt                  = no
req_extensions          = v3_req
default_md		= sha256

[ req_distinguished_name ]
CN                      = $domain

[ v3_req ]
subjectAltName          = $alt

[ req_attributes ]
EOF

echo "Written cnf file to $fn"

mkdir -p "$destdir" 2>/dev/null
if [ ! -d "$destdir" ]; then
  echo "Directory $destdir cannot be found or created, exiting." >&2
  exit 1
fi

# generate the keyfile first
case "$key" in
rsa ) 
    openssl genpkey -out "$destdir/key-$filebase.pem" -outform pem -algorithm rsa -pkeyopt rsa_keygen_bits:$bits
    ;;
ecc )
    [ "$bits" -gt 0 ] >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        # bits was not set for ECC, revert to default
        echo "!!! value of bits invalid for ECC, set to default prime256v1" >&2
        bits="prime256v1"
    fi
    openssl genpkey -out "$destdir/key-$filebase.pem" -outform pem -algorithm ec -pkeyopt ec_paramgen_curve:$bits
    ;;
* )
    echo "Unknown key type (internal error): $key" >&2
    exit 1
    ;;
esac

openssl req \
	-nodes \
	-config $fn \
	-new -key "$destdir/key-$filebase.pem" \
	-out "$destdir/request-$filebase.pem"

openssl req -in "$destdir/request-$filebase.pem" -text -out "$destdir/request-$filebase.txt"

chmod 0600 "$destdir/key-$filebase.pem"
mv "$fn" "$destdir/config-$filebase.cnf"

echo "----------------------------------------------------------------------"
echo "Domain name CN   = $domain"
echo "SubjectAltNames  = $alt"
echo "Key length $key  = $bits"

cat "$destdir/request-$filebase.pem"

echo "----------------------------------------------------------------------"
echo "left request in $destdir/request-$filebase.pem"
