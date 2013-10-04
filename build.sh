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

if [ "$OSTYPE" == "cygwin" ]; then rel=cygwin
elif [ "$OSTYPE" == "linux-gnu" ]; then rel=linux
else
	$lred; "Unknown Build Host"; $normal
	exit 1
fi

if [ ! -e ./`basename $0` ]; then
	cd $sourcedir
fi
if [ ! "$1" == "clean" ]; then
	$lyellow; echo "Building epk2extract"; $normal
	if [ -f "build_$rel" ]; then
		$lred; echo "A file named \"build_$rel\" exists. Please move it"; $normal
		exit 1
	elif [ ! -e "build_$rel" ]; then
		mkdir build_$rel
	fi

	cd build_$rel
	if [ "$rel" == "cygwin" ]; then
		cmake .. -DCMAKE_LEGACY_CYGWIN_WIN32=0
	else
		cmake ..
	fi
	make
	if [ ! $? == 0 ]; then
		$lred; echo "Build Failed!"; $normal
		exit 1
	else
		if [ "$rel" == "linux" ]; then
			cp src/epk2extract .
		elif [ "$rel" == "cygwin" ]; then
			cp src/epk2extract.exe .
			if [ "$HOSTTYPE" == "i686" ]; then #cygwin32
				sharedlibs=("cygz.dll" "cygwin1.dll" "cyglzo2-2.dll" "cyggcc_s-1.dll" "cygcrypto-1.0.0.dll")
			elif [ "$HOSTTYPE" == "x86_64" ]; then #cygwin64
				sharedlibs=("cygz.dll" "cygwin1.dll" "cyglzo2-2.dll" "cygcrypto-1.0.0.dll")
			fi
			for cyglib in ${sharedlibs[@]}; do
				$white; echo "Installing $cyglib"; $normal
				islibok=$(which "$cyglib" &>/dev/null; echo $?)
				if [ $islibok == 0 ]; then
					cp `which $cyglib` .
				else
					$lred
					echo "Something wrong! $cyglib not found."
					echo "Verify your cygwin installation and try again."
					$normal
					exit 1
				fi
			done
		fi
		$lgreen; echo "Build Completed!"; $normal
		exit 0
	fi
else
	$lyellow; echo "Removing epk2extract build directory"; $normal
	if [ -d "build_$rel" ]; then
		yes | rm -r build_$rel
	fi
	if [ ! -d "build_$rel" ]; then
		$lgreen; echo "Done!"; $normal
		exit 0
	else
		$lred; echo "Error!"; $normal
		exit 1
	fi
fi
