#
# @(#)$Id$
# 
# insatll the scripts
#
all: install

install:
	scp -p {README.txt,*.sh} webca@streng:/home/webca/html/tcs/
	scp -p {README.txt,*.sh} davidg@rakel:/project/srv/www/site/software/html/experimental/tcstools/
	cp -p *.sh ~/bin/

