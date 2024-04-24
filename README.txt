-----------------------------------------------------------------------------
TCStools - TCS Generation 4 (2020 edition)
-----------------------------------------------------------------------------

About
-----
The "tcsg4" and "sg*" scripts are for use with the 4th generation GEANT TCS
service (using Sectigo as a back-end operator). The scripts for TCSG3, that
used DigiCert as a back-end, are available under tcsg3/, and may still be
useful for other DigiCert customers. 
We apologize for the rather haphazard code layout, which is most certainly
'hackish' and originated as demonstrators or local scripts. We encourage 
everyone to make improvements or do code cleanup.  The shell scripts are
written so as to require minimal dependencies (usually only OpenSSL and 
basic utilities like ls, awk, or grep)

Some additional utility scripts useful for inspecting and debugging
certificate issues are included:
- probcert: connect to an SSL server or read a certificate or key file
  and display key attributes of the certificate found (expiry, SANs, modulus)
- listcerts.sh: list subject and issuer of all the PEM blobs in a file
- tcsg4-clean-certchain: remove archaic/broken certificates from a certificate
  chain (e.g. the AAA Certificate Services one). Takes stdin, writes stdout

! This also includes the scripts to request and retrieve certificates that are 
! issued through the Sectigo interface SCM. Using SCM without fixing up what 
! it returns to you can cause serious issues - always post-process server 
! certificates issued by and retrieved via SCM to correct for the SCM bugs!

*** tcsg4-install-servercert.sh
    Retrieve and regularize SSL server certificates for use

Import/regularisation scripts that rectify certificate chain issues for 
server certificates. Required for web servers to fix ordering and get 
appropriate chain files for Apache, IIS, and NGinx

  Usage: tcsg4-install-servercert.sh [-d destdir] [-r|-R] [-f]
       [-b backupprefix] <PKCS7.p7b> | EnrollmentID | p7b-URL

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


*** tcsg4-request.sh
    Create certificate requests (CSR) with alternative names

Create the most compatible CSRs, that will work with both OV and EV requests
and for EV anchors. Supports unlimited alternative names, wildcard certs, and
can generate both RSA and ECC requests. Can be fed with the output of existing
certificates ("openssl x509 -text") and will automatically remove any "DNS:"
and superfluous comma's in the list.
For ECC, use only P256 and P384. Sectigo does not support ec25519 :(

  Usage: tcsg4-request.sh [-d destdir] hostname [hostname ...]

   -d destdir   write result files to <destdir>
                (default: ./tcs-<hostname>/)
   -b bits      use <bits> for RSA key length (default: 2048) or curve for
                ECC (e.g. "prime256v1", set explicitly)
   -f | --force overwrite existing files
   -E | --ecc   generate ECC cert (remember to set -b to the curve!)

   hostname     hostname (FQDN) to be included in the request
                Any literal string "WILDCARD" will be replaced by
                a "*" in the hostname - it should ONLY be included as
                the first element of the fqdn, and MUST be on its own
     (the list of hostnames may be separated by spaces or commas)


*** tcsg4-install-credential.sh
    Unpack, regularise, and install personal and IGTF personal credentials

Convert the "p12" blob you get from Sectigo into useful formats with the 
script below.  Never use the blob as-is, not even for import into a browser 
or email client! - on Linux, MacOS, and Cygwin systems, always regularise 
it first with the install script, or it may break both you and the world.
Especially useful for IGTF client certificates, as it automatically 
installs also your .globus/ unpacked credentials!
See the step-by-step guide at 
  https://ca.dutchgrid.nl/tcs/TCS-enduser-request-guide-NL-2020-04.pdf
and the documentation pages from https://ca.dutchgrid.nl/tcs/

  Usage: tcsg4-install-credential.sh [-d destdir] [-p passfile] [-r|-R] [-f]
       [-n name] [-b backupprefix] [--csr] [--newpass] <PKCS12.p12>

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
   --newpass     ask for a new password for resulting credential secrets

   <PKCS12.p12>  filename of the blob produced by Sectigo

  Notice: do NOT import the blob from Sectigo directly into
  anything, since it will corrupt your key chain. Always use
  the "package-<name>.p12" file created by this script


*** nik-acme-certupdate
    ACME External Key Binding managed/protected client

Update (when needed) a certificate using the ACME protocol with pre-validated
domains, e.g., from the TCSG4 Sectigo ACME endpoints (but any EAB ACME 
endpoint can be used). It will check the domain list for this host, make 
sure the installed certificates (by default in /etc/pki/tls/tcsg4/) are 
as-expected, and will renew them when needed - because the domain list changed
or the cert will soon expire. The script is intentionally paranoid, even more 
so that certbot, so that there is always a reasonable cert remaining. 
It optionally cleanses archaic and wrong roots from the certificate chain (as
is needed for AAA Certificate Services by Sectigo).

This utility is particularly suited to be invoked from cron - it will just
check and do nothing unless there is actually actions required. It will not
even talk to the ACME endpoint if everything is fine. You can run it as 
often as you want, but typically:

  45 8 * * 1,3,4 root /usr/local/bin/nik-acme-certupdate

is a good startingpoint.

Prerequisites: bash, certbot, openssl [v1+], sed, date, mktemp, diff, logger
     Optional: tcsg4-clean-certchain [to remove antiquated certificate chain]

The "TARGETDIR" variable sets the place where consumers (like a web server 
daemon) will expect to find a stable set of keys and certificates. So you
should not point the web server to directly read from the things generated
by certbot. It matches the tcsg4-install-servercert.sh directory structure.

Other useful things go into the mndatory configuration file at
/usr/local/etc/nik-acme-certupdate.config (by default). 

It should contain at keast KID and HMAC, and may override the local defaults:

 KID=Dc1...
 HMAC=mv_3kv....
 CERTSERVER=https://acme.enterprise.sectigo.com
 CERTNAME=`hostname -f`
 DOMAINS=....
 TARGETOWNER=openldap
 TARGETGROUP=root
 TARGETPERMS=0640
 TARGETDIR=/etc/pki/tls/tcsg4
 POSTRUN=



-----------------------------------------------------------------------------
@(#)$Id$
Shell scripts by David Groep, Nikhef.
With contributions by Francesco Giacomini and Mischa Salle.
API tool sgcli.py by Dennis van Dok, Nikhef.
Apache 2.0 License - https://www.apache.org/licenses/LICENSE-2.0
