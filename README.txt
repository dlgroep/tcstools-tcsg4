-----------------------------------------------------------------------------
TCS Generation 4 (2020 edition)
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

-----------------------------------------------------------------------------
@(#)$Id$
Shell scripts by David Groep, Nikhef.
API tool sgcli.py by Dennis van Dok, Nikhef.
Apache 2.0 License - https://www.apache.org/licenses/LICENSE-2.0
