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
# in addition requires curl if you use URLs for the PKCS#7 input
#
#
destdir=.
DATE=`date +%Y%m%d-%H%M%S`
progname=`basename "$0"`
bckprefix=backup
makecsr=0
nameformat=friendly
certfn=

# ############################################################################
# usage help and instructions
#
help() { cat <<EOF
Usage: tcsg4-install-servercert.sh [-d destdir] [-r|-R] [-f]
       [-b backupprefix] <PKCS7.p7b>

   -d destdir    write result files to <destdir>
   -r            use EEC commonName as basis for new filenames
   --no-rename   use the base filename of the P7B file for new filenames
   -R            use EEC commonName and date as basis for filenames
   -f            do not make backups of existing files
   -b bckprefix  prefix of the filename to use when making backups

   <PKCS7.p7b>   filename of the blob produced by Sectigo
                 or URL to the PKCS#7 blob from the success email
                 (https://cer.../ssl?action=download&sslId=1234567&format=bin)
                 remember to "quote" the URL to preserve the ampersands
                 or Self-Enrollment ID number (numeric)

EOF
   return;
}

# ############################################################################
#
while [ $# -gt 0 ]; do
case "$1" in
-r | --rename )            nameformat="friendly"; shift 1 ;;
-x | --no-rename )         nameformat=""; shift 1 ;;
-R | --rename-with-date )  nameformat="dated"; shift 1 ;;
-f | --force )             bckprefix=""; shift 1 ;;
-h | --help )              help ; exit 0 ;;
-b | --backupprefix )      bckprefix="$2"; shift 2 ;;
-d | --destination )       destdir="$2"; shift 2 ;;
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
# retrieve PKCS#7 from URL, if URL given (beware of quoting the ampersand)
# or from order number
#
[ "$pkfile" -gt 0 ] > /dev/null 2>&1
if [ $? -eq 0 ]; then
  # this was a pure number, so an order ID
  echo "Recognised order ID $pkfile, downloading"
  pkfile="https://cert-manager.com/customer/surfnet/ssl?action=download&sslId=${pkfile}&format=bin"
fi

case "$pkfile" in
https://*format=bin | https://*format=base64 )
    sslid=`echo "$pkfile"|sed -e's/.*sslId=\([0-9]*\).*/\1/'`
    [ "$sslid" -gt 0 ] >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "URL provided is not a Sectigo SSL PKCS#7 enrollment result" >&2
        exit 1
    fi
    curl -s -o "sectigo-order-$sslid.p7b" "$pkfile"
    if [ $? -ne 0 ]; then
        echo "URL cannot be downloaded ($pkfile)" >&2
        exit 1
    fi
    case "$pkfile" in
        *format=base64 )
            mv "sectigo-order-$sslid.p7b" "sectigo-order-$sslid.p7b.pem"
            openssl pkcs7 \
                -inform pem  -in  "sectigo-order-$sslid.p7b.pem" \
                -outform der -out "sectigo-order-$sslid.p7b"
        ;;
    esac
    if [ ! -s "sectigo-order-$sslid.p7b" ]; then
        echo "URL download result empty in sectigo-order-$sslid.p7b " >&2
        echo "  (source $pkfile)" >&2
        exit 1
    fi
    pkfile="sectigo-order-$sslid.p7b"
    ;;
esac


# ############################################################################
# input validation
#
if [ ! -r "$pkfile" ]; then echo "Cannot read $pkfile" >&2; exit 1; fi

case "$pkfile" in
*.p7b ) credbase=`basename "$pkfile" .p7b` ;;
* )  echo "Unlikely PKCS#12 file: $pkfile" >&2 ; exit 2 ;;
esac

# ############################################################################
# extraction of Sectigo blob of p7b
#
tempdir=`mktemp -d tcsg4unpack.XXXXXX`

if [ ! -d "$tempdir" ]; then
  echo "Error creating temporary working directory here" >&2
  exit 1
fi

openssl pkcs7 -inform der -in "$pkfile" -print_certs \
    -out "$tempdir/p7b-$credbase.pem"

if [ $? -ne 0 ]; then
  echo "Error: cannot extract data from PKCS7 file $pkfile" >&2
  echo "       PASSPHRASE INCORRECT?" >&2
  exit 3
fi

if [ ! -s "$tempdir/p7b-$credbase.pem" ]; then
  echo "Error: cannot extract data from PKCS7 file $pkfile" >&2
  echo "       resulting direct-rendered p7b file not found" >&2
  exit 4
fi

if [ `grep -c CERTIFICATE "$tempdir/p7b-$credbase.pem"` -eq 0 ]; then
  echo "Error: cannot extract data from PKCS7 file $pkfile" >&2
  echo "       resulting p7b file has no certificate material" >&2
  exit 4
fi

# extract 
awk '
  BEGIN { icert = 0; }
  /^-----BEGIN CERTIFICATE-----$/ {
    icert++;
    print $0 > "'$tempdir/cert-'"icert"'-$credbase.pem'";
    do {
      getline ln;
      print ln > "'$tempdir/cert-'"icert"'-$credbase.pem'";
    } while ( ln != "-----END CERTIFICATE-----" );
  }
' "$tempdir/p7b-$credbase.pem" 

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

  # these CAs as intermediate subjects are known useless
  case "$certcn" in
  "AAA Certificate Services" ) continue ;;
  "USERTrust RSA Certification Authority" ) continue ;;
  * ) ;;
  esac

  if [ $certisca -eq 0 ]; then
    certfn=`echo "$certcn" | sed -e 's/[^-a-zA-Z0-9_\.]/_/g'`
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
      echo -ne "" > "$destdir/chain-$credbase.pem"
    fi
    cat $i >> "$destdir/chain-$credbase.pem"
  fi

  if [ $certisca -eq 0 ]; then
    if [ -f "$destdir/cert-$credbase.pem" ]; then
      mv "$destdir/cert-$credbase.pem" "$destdir/$bckprefix.$DATE.cert-$credbase.pem"
    fi
    cat $i > "$destdir/cert-$credbase.pem"
  fi

done

# ############################################################################
# cleanup intermate files and name output properly
#
rm "$tempdir"/cert-*-$credbase.pem
rm "$tempdir"/p7b-$credbase.pem
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
else
  certfn="$credbase"
fi

# ############################################################################
# create the nginx compatible single file: cert+chain concatenated
#
cat "$destdir/cert-$certfn.pem" "$destdir/chain-$certfn.pem" \
    > "$destdir/nginx-$certfn.pem"

# ############################################################################
# inform user of result and of globus compatibility
#
echo "The following files have been created for you:"
echo -ne "  " ; ls -l1a "$destdir/cert-$certfn.pem"
echo -ne "  " ; ls -l1a "$destdir/chain-$certfn.pem"

#
#
# ############################################################################
