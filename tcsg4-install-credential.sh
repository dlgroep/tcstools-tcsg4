#! /bin/sh
#
# @(#)$Id$
# rev 2
#
# TCS G4 client certificate format management tool for POSIX systems
# including installation to Grid Community Toolkit (formerly Globus)
# user credential directory formats
#
# Requirements: sh, awk, sed, openssl, date, mktemp, ls, 
#               mkdir, rmdir, mv, basename, grep, chmod
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
#
destdir=${HOME}/.globus
DATE=`date +%Y%m%d-%H%M%S`
progname=`basename "$0"`
bckprefix=backup
makecsr=0
nameformat=
certfn=

# ############################################################################
# usage help and instructions
#
help() { cat <<EOF
Usage: tcsg4-install-credential.sh [-d destdir] [-p passfile] [-r|-R] [-f]
       [-n name] [-b backupprefix] <PKCS12.p12>

   -d destdir    write result files to <destdir>
                 if <destdir> contains "globus", also make the
                 symlinks userkey.pem and usercert.pem for GCT tools
   -p passfile   file with the password to use (same for input
                 and for output PKCS#12 and private keys)
   -r            use EEC commonName as basis for new filenames
   -R            use EEC commonName and date as basis for filenames
   -f            do not make backups of existing files
   -n name       set friendly name of the credential in corrected
                 PKCS#12 (.p12) file produced. If unset, is taken
                 from the commonName of the EEC and issuance date
   -b bckprefix  prefix of the filename to use when making backups
   --csr         generate a CSR request file for future use in destdir

   <PKCS12.p12>  filename of the blob produced by Sectigo

Notice: do NOT import the blob from Sectigo directly into
anything, since it will corrupt your key chain. Always use
the "package-<name>.p12" file created by this script

EOF
   return;
}

# ############################################################################
#
while [ $# -gt 0 ]; do
case "$1" in
-r | --rename )            nameformat="friendly"; shift 1 ;;
-R | --rename-with-date )  nameformat="dated"; shift 1 ;;
--csr )                    makecsr=1; shift 1 ;;
-f | --force )             bckprefix=""; shift 1 ;;
-h | --help )              help ; exit 0 ;;
-b | --backupprefix )      bckprefix="$2"; shift 2 ;;
-n | --name )              friendlyname="$2"; shift 2 ;;
-d | --destination )       destdir="$2"; shift 2 ;;
-p | --passfile )          passfile="$2" ; shift 2 ;;
-* )                       echo "Unknown option $1, exiting" >&2 ; exit 1 ;;
*  )                       break ;;
esac
done

case $# in
0 ) help ; exit 0 ;;
1 ) pkfile="$1"; break ;;
* ) echo "Too many arguments." >&2 ; exit 1 ;;
esac

# ############################################################################
# input validation
#
if [ ! -r "$pkfile" ]; then echo "Cannot read $pkfile" >&2; exit 1; fi

case "$pkfile" in
*.p12 ) credbase=`basename "$pkfile" .p12` ;;
*.pfx ) credbase=`basename "$pkfile" .pfx` ;;
* )  echo "Unlikely PKCS#12 file: $pkfile" >&2 ; exit 2 ;;
esac

# ############################################################################
# obtain password from somewhere
#
if [ -n "$passfile" ]; then
  if [ ! -r "$passfile" ]; then
    echo "Error: cannot read password from $passfile" >&2 ; exit 1
  fi
  PW=`head -1 "$passfile"`
else
  while [ x"$PW" = x"" ]; do
    echo -ne "Passphrase (existing) for your secret key: "
    stty -echo ; read PW ; stty echo
    echo ""
  done
fi
if [ -z "$PW" ]; then echo "Empty password is not allowed" >&2; exit 2; fi
export PW

# ############################################################################
# extraction of Sectigo blob of crap
#
tempdir=`mktemp -d tcsg4unpack.XXXXXX`

if [ ! -d "$tempdir" ]; then
  echo "Error creating temporary working directory here" >&2
  exit 1
fi

openssl pkcs12 -nomacver -password env:PW -in "$pkfile" \
    -passout env:PW -out "$tempdir/crap-$credbase.pem"

if [ $? -ne 0 ]; then
  echo "Error: cannot extract data from PKCS12 file $pkfile" >&2
  echo "       PASSPHRASE INCORRECT?" >&2
  exit 3
fi

if [ ! -s "$tempdir/crap-$credbase.pem" ]; then
  echo "Error: cannot extract data from PKCS12 file $pkfile" >&2
  echo "       resulting direct-rendered crap file not found" >&2
  exit 4
fi

if [ `grep -c PRIVATE "$tempdir/crap-$credbase.pem"` -eq 0 ]; then
  echo "Error: cannot extract data from PKCS12 file $pkfile" >&2
  echo "       resulting crap file has no key material" >&2
  exit 4
fi

if [ `grep -c CERTIFICATE "$tempdir/crap-$credbase.pem"` -eq 0 ]; then
  echo "Error: cannot extract data from PKCS12 file $pkfile" >&2
  echo "       resulting crap file has no certificate material" >&2
  exit 4
fi

# extract 
awk '
  BEGIN { icert = 0; }
  /^-----BEGIN ENCRYPTED PRIVATE KEY-----$/ {
    print $0 > "'$tempdir/key-$credbase.pem'";
    do {
      getline ln;
      print ln > "'$tempdir/key-$credbase.pem'";
    } while ( ln != "-----END ENCRYPTED PRIVATE KEY-----" );
  }
  /^-----BEGIN CERTIFICATE-----$/ {
    icert++;
    print $0 > "'$tempdir/cert-'"icert"'-$credbase.pem'";
    do {
      getline ln;
      print ln > "'$tempdir/cert-'"icert"'-$credbase.pem'";
    } while ( ln != "-----END CERTIFICATE-----" );
  }
' "$tempdir/crap-$credbase.pem" 

# ############################################################################
# generate per-certificate and key output files
#
[ -d "$destdir" ] || mkdir -p "$destdir"

havewrittenchain=0
for i in "$tempdir"/cert-*-"$credbase".pem
do
  certcn=`openssl x509 -noout -subject -nameopt oneline,sep_comma_plus \
    -in "$i" | \
    sed -e 's/.*CN = \([a-zA-Z0-9\._][- a-zA-Z0-9:\._@]*\).*/\1/'`
  issuercn=`openssl x509 -noout -issuer -nameopt oneline,sep_comma_plus \
    -in "$i" | \
    sed -e 's/.*CN = \([a-zA-Z0-9\._][- a-zA-Z0-9:\._@]*\).*/\1/'`

  certdate=`openssl x509 -noout -text -in "$i" | \
    awk '/    Not Before:/ { print $4,$3,$6; }'`
  certisca=`openssl x509 -noout -text -in "$i" | \
    awk 'BEGIN { ca=0; } 
         /CA:FALSE/ { ca=0; } /CA:TRUE/ { ca=1; } 
         END {print ca;}'`

  if [ "$certcn" = "$issuercn" -o "$issuercn" = "AddTrust External CA Root" ] 
  then
    continue
  fi

  if [ $certisca -eq 0 ]; then
    certfn=`echo "$certcn" | sed -e 's/[^-a-zA-Z0-9_]/_/g'`
    certfndated=`echo "$certcn issued $certdate" | \
                 sed -e 's/[^-a-zA-Z0-9_]/_/g'`
    echo "Processing EEC certificate: $certcn"
    friendlyname="${friendlyname:-$certcn issued $certdate}"
    echo "  (friendly name: $friendlyname)"
  fi

  if [ $certisca -eq 1 ]; then
    echo "Processing CA  certificate: $certcn"
    if [ $havewrittenchain -eq 0 ]; then
      if [ -f "$destdir/chain-$credbase.pem" -a -n "$bckprefix" ]; then
        mv "$destdir/chain-$credbase.pem" \
           "$destdir/$bckprefix.$DATE.chain-$credbase.pem"
      fi
      havewrittenchain=1
      echo "" > "$destdir/chain-$credbase.pem"
    fi
    cat $i >> "$destdir/chain-$credbase.pem"
  fi

  if [ $certisca -eq 0 ]; then
    if [ -n "$pkcs12eec" ]; then
      echo "Error: there are multiple EEC certificates in the blob" >&2
      echo "       this script cannot handle this case, sorry!" >&2
      exit 2
    fi
    pkcs12eec="$i"
    if [ -f "$destdir/cert-$credbase.pem" ]; then
      mv "$destdir/cert-$credbase.pem" "$destdir/$bckprefix.$DATE.cert-$credbase.pem"
    fi
    cat $i > "$destdir/cert-$credbase.pem"
  fi

done

echo "Processing EEC secret key"
if [ ! -s "$tempdir/key-$credbase.pem" ]; then
  echo "Error: cannot find secret key file which should have been there" >&2
  echo "       internal error in AWK section (P1)" >&2
  exit 5
fi
if [ `grep -c PRIVATE "$tempdir/key-$credbase.pem"` -eq 0 ]; then
  echo "Error: cannot find key in keyfile which should have been there" >&2
  echo "       internal error in AWK section (P2)" >&2
  exit 5
fi

if [ -f "$destdir/key-$credbase.pem" -a -n "$bckprefix" ]; then
  mv "$destdir/key-$credbase.pem" "$destdir/$bckprefix.$DATE.key-$credbase.pem"
fi
cat "$tempdir/key-$credbase.pem" > "$destdir/key-$credbase.pem"

# not all filesystems support perms, so ignore errors
chmod go-rwx "$destdir/key-$credbase.pem" 2>/dev/null 
chmod go-rwx "$destdir/cert-$credbase.pem" 2>/dev/null 

echo "Repackaging $friendlyname as PKCS12"
if [ -f "$destdir/package-$credbase.p12" -a -n "$bckprefix" ]; then
  mv "$destdir/package-$credbase.p12" \
     "$destdir/$bckprefix.$DATE.package-$credbase.p12"
fi
openssl pkcs12 -export \
    -passin env:PW -inkey "$tempdir/key-$credbase.pem" \
    -certfile "$destdir/chain-$credbase.pem" \
    -name "$friendlyname" -in "$pkcs12eec" \
    -passout env:PW -out "$destdir/package-$credbase.p12"

if [ $? -ne 0 ]; then
  echo "Error: something went wrong creating the normalised package" >&2
  echo "       non-zero return code from openssl in PKCS12 export (X1)" >&2
  exit 5
fi
if [ ! -s "$destdir/package-$credbase.p12" ]; then
  echo "Error: something went wrong creating the normalised package" >&2
  echo "       internal error in PKCS12 export (X2)" >&2
  exit 5
fi

# not all filesystems support perms, so ignore errors
chmod go-rwx "$destdir/package-$credbase.p12" 2>/dev/null 

# ############################################################################
# cleanup intermate files and name output properly
#
rm "$tempdir"/cert-*-$credbase.pem
rm "$tempdir"/crap-$credbase.pem
rm "$tempdir"/key-$credbase.pem
rmdir "$tempdir"
if [ $? -ne 0 ]; then
  echo "Error: cannot remove working directory $tempdir" >&2
  echo "       internal inconsistency or prior error encountered" >&2
fi

# rename, if so required
if [ -n "$nameformat" ]; then
  if [ "$nameformat" = "friendly" ]; then
    certfn="${certfn:-$credbase}"
  elif [ "$nameformat" = "dated" ]; then
    certfn="${certfndated:-$credbase}"
  else
    echo "Unknown filename format, error" >&2
    exit 2
  fi
  mv "$destdir/cert-$credbase.pem"    "$destdir/cert-$certfn.pem"
  mv "$destdir/chain-$credbase.pem"   "$destdir/chain-$certfn.pem"
  mv "$destdir/key-$credbase.pem"     "$destdir/key-$certfn.pem"
  mv "$destdir/package-$credbase.p12" "$destdir/package-$certfn.p12"
else
  certfn="$credbase"
fi

# make CSR for future use if requested
if [ "$makecsr" -ne 0 ]; then
  echo "Generating CSR file for future use and renewal"
  if [ -f "$destdir/request-$credbase.pem" -a -n "$bckprefix" ]; then
    mv "$destdir/request-$credbase.pem" \
       "$destdir/$bckprefix.$DATE.request-$credbase.pem"
  fi

  certsubject=/`openssl x509 -noout -subject -nameopt oneline,sep_comma_plus \
    -in "$destdir/cert-$certfn.pem" | \
    sed -e 's/^subject= *//;s/,/\//g;s/ = /=/g'`

  echo "  subject: $certsubject"

  openssl req -new \
    -key "$destdir/key-$certfn.pem" -passin env:PW \
    -subj "$certsubject" \
    -out "$destdir/request-$certfn.pem"
fi

# ############################################################################
# inform user of result and of globus compatibility
#
echo "The following files have been created for you:"
echo -ne "  " ; ls -l1a "$destdir/cert-$certfn.pem"
echo -ne "  " ; ls -l1a "$destdir/chain-$certfn.pem"
[ -f "$destdir/request-$certfn.pem" ] && \
  ( echo -ne "  " ; ls -l1a "$destdir/request-$certfn.pem" )
echo -ne "  " ; ls -l1a "$destdir/key-$certfn.pem"
echo -ne "  " ; ls -l1a "$destdir/package-$certfn.p12"

# globus-ify pertinent dest directories
case "$destdir" in
*globus* )
    echo "Making Grid Community Toolkit compatible link in $destdir"
    if [ -f "$destdir/userkey.pem" -a -n "$bckprefix" ]; then
        echo "  backing up userkey.pem to ""$bckprefix.$DATE.userkey.pem"
	mv "$destdir/userkey.pem" "$destdir/$bckprefix.$DATE.userkey.pem"
    fi
    echo "  userkey.pem"
    ln -sfnT "key-$certfn.pem" "$destdir/userkey.pem"
    if [ -f "$destdir/usercert.pem" -a -n "$bckprefix" ]; then
        echo "  backing up usercert.pem to $bckprefix.$DATE.usercert.pem"
	mv "$destdir/usercert.pem" "$destdir/$bckprefix.$DATE.usercert.pem"
    fi
    echo "  usercert.pem"
    ln -sfnT "cert-$certfn.pem" "$destdir/usercert.pem"
    ;;
esac

#
#
# ############################################################################
