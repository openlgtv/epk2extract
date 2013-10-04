#!/bin/bash
#============================================================================
# Authors      : sirius, lprot, smx
# Copyright   : published under GPL
#============================================================================

normal='tput sgr0'
lred='printf \033[01;31m'
lgreen='printf \033[01;32m'
lyellow='printf \033[01;33m'
white='printf \033[01;37m'

cwd=$(pwd)
sourcedir=$(cd `dirname $0`; pwd -P)

if [ "$OSTYPE" == "cygwin" ]; then rel=build_cygwin
elif [ "$OSTYPE" == "linux-gnu" ]; then rel=build_linux
else
	$lred; "Can't build - unknown OS type. Aborting..."; $normal
	exit 1
fi

if [ ! -e ./`basename $0` ]; then
	cd $sourcedir
fi
if [ ! "$1" == "clean" ]; then
	$lyellow; echo "Building epk2extract"; $normal
	if [ ! -e "$rel" ]; then
		mkdir $rel
	fi

	cmake .
	cd src
	make

	if [ ! $? == 0 ]; then
		$lred; echo "Build Failed!"; $normal
		exit 1
	else
		if [ "$rel" == "build_linux" ]; then
			mv epk2extract ../$rel
		elif [ "$rel" == "build_cygwin" ]; then
			mv epk2extract.exe ../$rel
			if [ "$HOSTTYPE" == "i686" ]; then #cygwin32
				sharedlibs=("cygz.dll" "cygwin1.dll" "cyglzo2-2.dll" "cyggcc_s-1.dll" "cygcrypto-1.0.0.dll")
			elif [ "$HOSTTYPE" == "x86_64" ]; then #cygwin64
				sharedlibs=("cygz.dll" "cygwin1.dll" "cyglzo2-2.dll" "cygcrypto-1.0.0.dll")
			fi
			for cyglib in ${sharedlibs[@]}; do
				$white; echo "Installing $cyglib"; $normal
				islibok=$(which "$cyglib" &>/dev/null; echo $?)
				if [ $islibok == 0 ]; then
					cp `which $cyglib` ../$rel
				else
					$lred
					echo "Something wrong! $cyglib not found."
					echo "Verify your cygwin installation and try again."
					$normal
					exit 1
				fi
			done
		fi
		$lgreen; echo "Build completed!"; $normal
		exit 0
	fi
else
	$lyellow; echo "Removing cmake cache and make files"; $normal
	find . -type f -name "CMakeCache.txt" -delete
	find . -type f -name "Makefile" -delete
	find . -type f -name "cmake_install.cmake" -delete
	find . -type f -name "*.a" -delete
	find . -type f -name "epk2extract" -delete
	find . -type f -name "epk2extract.exe" -delete
	find . -depth -name "CMakeFiles" -exec rm -rf '{}' \;
	$lgreen; echo "Done!"; $normal
	exit 0
fi
