#!/bin/bash
#============================================================================
# Authors      : sirius, lprot, smx
# Copyright   : published under GPL
#============================================================================

normal='tput sgr0'
lred='printf \033[01;31m'
lgreen='printf \033[01;32m'
lyellow='printf \033[01;33m'
lblue='printf \033[01;34m'
white='printf \033[01;37m'

cwd=$(pwd)
srcdir=$(cd `dirname $0`; pwd -P)

exe=("epk2extract" "tools/lzhsenc" "tools/lzhs_scanner" "tools/idb_extract")

if [ "$OSTYPE" == "cygwin" ]; then rel=build_cygwin
elif [[ "$OSTYPE" =~ "linux" ]]; then rel=build_linux
elif [[ "$OSTYPE" =~ "darwin" ]]; then rel=build_osx
else
	$lred; "Can't build - unknown OS type. Aborting..."; $normal
	exit 1
fi

installdir=$srcdir/$rel
objdir=$installdir/obj

if [ ! -e ./`basename $0` ]; then
	cd $srcdir
fi
if [ ! "$1" == "clean" ]; then
	$lyellow; echo "Building epk2extract"; $normal
	if [ ! -e "$rel/obj" ]; then
		mkdir -p $rel/obj
	fi

	cd $objdir
	cmake $srcdir
	make
	RESULT=$?
	cd src

	if [ ! $RESULT -eq 0 ]; then
		$lred; echo "Build Failed!"; $normal
		exit 1
	else
		if [ "$rel" == "build_cygwin" ]; then
			for exe in ${exe[@]}; do
				cp $exe.exe $installdir/
			done
			if [ "$HOSTTYPE" == "i686" ]; then #cygwin32
				sharedlibs=("cygz.dll" "cygwin1.dll" "cyglzo2-2.dll" "cyggcc_s-1.dll" "cygcrypto-1.0.0.dll" "cygstdc++-6.dll")
			elif [ "$HOSTTYPE" == "x86_64" ]; then #cygwin64
				sharedlibs=("cygz.dll" "cygwin1.dll" "cyglzo2-2.dll" "cygcrypto-1.0.0.dll" "cyggcc_s-seh-1.dll" "cygstdc++-6.dll")
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
		else
			for exe in ${exe[@]}; do
				cp $exe $installdir/
			done
		fi

		cd ..
		if [ -d "$srcdir/keys" ]; then
			for key in $(find ${srcdir}/keys -iname "*.pem" -or -iname "*.key" | sort); do
				$lblue; echo "Installing $(basename $key)"; $normal
				cp $key $installdir/
			done
		fi
		$lgreen; echo "Build completed!"; $normal
		exit 0
	fi
else
	$lyellow; echo "Removing cmake cache and make files"; $normal
	rm -r $objdir
	if [ -d "$installdir" ]; then
		$lyellow; echo "Removing build dir"; $normal
		rm -r "$installdir"
	fi
	$lgreen; echo "Done!"; $normal
	exit 0
fi
