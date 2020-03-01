#!/bin/bash -e
install_linux(){
	sudo apt-get update -qq
	sudo apt-get install -qq liblzo2-dev libssl-dev libc6-dev
}

install_osx(){
	brew update
	brew install zlib lzo openssl@1.1
	cd /usr/local/include 
	ln -s ../opt/openssl/include/openssl .
}

case $TRAVIS_OS_NAME in
	osx) install_osx;;
	linux) install_linux;;
	*)
		echo "Unsupported OS ${TRAVIS_OS_NAME}"
		exit 1
		;;
esac
