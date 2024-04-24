#
# @(#)$Id$
# 
# install the scripts
#
all: install

install:
	cp -p *.sh probecert tcsg4-clean-certchain ~/bin/
	scp -p {README.txt,probecert,nik-acme-certupdate,tcsg4-clean-certchain,*.sh,sgtcs-cli.py} webca@streng:/home/webca/html/tcs/
	scp -p {README.txt,probecert,nik-acme-certupdate,tcsg4-clean-certchain,*.sh,sgtcs-cli.py} davidg@rakel:/project/srv/www/site/software/html/experimental/tcstools/

