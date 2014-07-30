#!/usr/bin/env python2
import os, struct, sys, binascii, datetime, fnmatch
def allzero(string):
        for x in string:
                if ord(x):
                        return False
        return True

def allFF(string):
        for x in string:
		if ord(x) != 0xFF:
			return False
	return True

def validate(date_text):
	try:
		datetime.datetime.strptime(date_text, '%Y-%m-%d')
	except ValueError:
		#raise ValueError("Invalid Partition Table File")
		sys.exit("Invalid Partition Table File")

def fancyprint(str, pad):
	astr = "|"
	for c in range(pad):
		astr+=" "
	astr+=str
	for c in range(pad):
		astr+=" "
	astr+= "|"
	
	for c in range(len(astr)):
		sys.stdout.write('-')
	print ""
	print astr
	for c in range(len(astr)):
		sys.stdout.write('-')
	print ""


if not len(sys.argv) == 2:
	print "Usage: %s part.pak" % sys.argv[0]
	sys.exit()
	
if not os.path.exists(sys.argv[1]):
	sys.exit("Invalid file specified")

with open(sys.argv[1], "rb") as partpak:
	#partinfo struct, used by:
	#	mtk2013
	#	lg1154
	partmap_struct = "<4s4s4sB3x"
	device_struct = "<32sQQ4s4siI"
	part_struct = "<32sQQ32sIIBBI2x"
	(magic, cur_epk_ver, old_epk_ver, npartition) = struct.unpack(partmap_struct, partpak.read(struct.calcsize(partmap_struct)))
	(devname, devsize, devphys, devvirt, devcached, devbandwith, devused) = struct.unpack(device_struct, partpak.read(struct.calcsize(device_struct)))
	devname = devname.replace("\x00","") #remove empty chars from string
	
	ismtk1 = fnmatch.fnmatchcase(devname, "mtk3569-emmc") #match mtk2012
	ismtkm1 = fnmatch.fnmatchcase(devname, "mtk5369-emmc") #match mtk2012
	ismtk2 = fnmatch.fnmatchcase(devname, "mtk3598-emmc") #match mtk2013
	ismtkm2 = fnmatch.fnmatchcase(devname, "mtk5398-emmc") #match mtk2013
	is1152 = fnmatch.fnmatchcase(devname, "l9_emmc") #match 1152
	is1154 = fnmatch.fnmatchcase(devname, "h13_emmc") #match 1154
	isbcm1	= fnmatch.fnmatchcase(devname, "bcm35xx_map0") #match broadcom
	isbcm2	= fnmatch.fnmatchcase(devname, "bcm35230_map0") #match broadcom
	ismstar= fnmatch.fnmatchcase(devname, "mstar_map0") #match mstar
	if ismtk1 or ismtkm1:
		model="Mtk 2012 - MTK5369"
	elif ismtk2 or ismtkm2:
		model="Mtk 2013 - MTK5398"
	elif is1152:
		model="LG1152"
	elif is1154:
		model="LG1154"
	elif isbcm1:
		model="BCM 2011 - BCM35230"
	elif isbcm2:
		model="BCM 2010 - BCM35XX"
	elif ismstar:
		model="Mstar Saturn/LM1"
	else:
		model="Unknown"

	if ismtk2 == False and is1154 == False:
	#alternative structs
		if ismtk1 == True or is1152 == True:
			#mixed struct, used by
			#	mtk2012:
			#	lg1152
			#
			#	partinfo header
			#	mtdinfo device struct
			#	Mixed mtdinfo AND partinfo struct
			#		32sII32s --> old mtdinfo part
			#		sIIBBI2x --> new partinfo part
			partpak.seek(0)
			partmap_struct = "<4s4s4sB3x"
			device_struct = "<32sII4s4siI"
			part_struct = "<32sII32sIIBBI2x"
			(magic, cur_epk_ver, old_epk_ver, npartition) = struct.unpack(partmap_struct, partpak.read(struct.calcsize(partmap_struct)))
			(devname, devsize, devphys, devvirt, devcached, devbandwith, devused) = struct.unpack(device_struct, partpak.read(struct.calcsize(device_struct)))
		else:
			#mtdinfo struct, used by:
			#	bcm
			#	lm1
			#	mstar
			partpak.seek(0)
			partmap_struct = "<4s4s4sBB2x"
			device_struct = "<32sII4s4siI"
			part_struct = "<32sII32sIIBBBx"
			(magic, cur_epk_ver, old_epk_ver, nmap, npartition) = struct.unpack(partmap_struct, partpak.read(struct.calcsize(partmap_struct)))
			(devname, devsize, devphys, devvirt, devcached, devbandwith, devused) = struct.unpack(device_struct, partpak.read(struct.calcsize(device_struct)))
			#mtdinfo struct supports 4 mtd devices, but LG uses only one nand/device
			#seek ahead the 3 empty slots
			partpak.read(struct.calcsize(device_struct)*3)
	
	devname = devname.replace("\x00","") #remove empty chars from string
	devsize = float(devsize)
	if devsize%(1024*1024*1024) == 0:
                #Gigabytes
		devsize = devsize/1024/1024/1024
		devsizeunit = "GB"
	else:
		#Small MTD, use Megabytes
		devsize = devsize/1024/1024
		devsizeunit = "MB"
		
	
	#swap magic byte array
	magic = list(magic)[::-1]
	
	#if epk fields are not empty, swap them
	if not allzero(cur_epk_ver) and not allzero(old_epk_ver):
		cur_epk_ver = list(cur_epk_ver)[::-1]
		old_epk_ver = list(old_epk_ver)[::-1]
		epk_ver = 1
	else:
		#empty apk fields, don't display
		epk_ver = 0
	
	#encode magic and epk data (if present) to hex
	for e in range(4):
		magic[e] = magic[e].encode("hex")
		if epk_ver == 1:
			cur_epk_ver[e] = cur_epk_ver[e].encode("hex")
			old_epk_ver[e] = old_epk_ver[e].encode("hex")
	
	#join epk data with dot (.)		
	cur_epk_ver = '.'.join([str(x) for x in cur_epk_ver])
	old_epk_ver = '.'.join([str(x) for x in old_epk_ver])
	
	#build magic string
	magic = magic[0]+magic[1]+"-"+magic[2]+"-"+magic[3]
	#check if it's a valid date
	validate(magic)
	
	fancyprint("Detected: "+model, 10)
	
	print "Partition Table Info:"
	print "-------------------------------"
	
	print "Date Magic: %s" %magic
	if not epk_ver == 0:
		print "Epk version: %s" % cur_epk_ver
		print "Old Epk version: %s" % old_epk_ver
	if not npartition == 1 and not npartition == 0:
		print "Partition Count: %d" % npartition
		
	print "MTD Name: %s, size %d %s" % (devname, devsize, devsizeunit)
	print "Partition Table:"
	print "-------------------------------"
		
	for part in range(npartition):
		(partname, partoff, partsize, partfn, partfs, partsw, partIsUsed, partIsValid, partflags) = struct.unpack(part_struct, partpak.read(struct.calcsize(part_struct)))
		partname = partname.strip()
		fancyprint("Partition "+str(part), 5)
                print "Name: \t\t\t %s"%partname
                if partsize%(1024*1024) == 0:
                        partsize = partsize/1024/1024
                        partsizeunit = "MB"
                elif partsize%1024 == 0:
                        partsize = partsize/1024
                        partsizeunit = "KB"
                else:
                        partsizeunit = "bytes"
                print "Partition Size: \t %d %s"%(partsize, partsizeunit)
                print "Filename: \t\t %s"%partfn
                partfs = float(partfs)
                if partfs%(1024*1024) == 0:
                        partfs = partfs/1024/1024
                        fsunit = "MB"
                elif partfs%1024 == 0:
                        partfs = partfs/1024
                        fsunit = "KB"
                else:
                        fsunit = "bytes"
                print "Filename Size: \t\t %d %s"%(partfs, fsunit)
                partsw="%08x"%partsw
                partsw=".".join(["".join(partsw[i:i+2]) for i in xrange(0, len(partsw), 2)])
                partflags = '{0:08b}'.format(partflags)
                partflags=int(partflags)
                isFixed = bool(partflags & 1)
                isMaster = bool(partflags & 2)
                isKey = bool(partflags & 4)
                isCache = bool(partflags & 8)
                isData = bool(partflags & 16)
                isSecure = bool(partflags & 32)
                isErase = bool(partflags & 64)
                partflags = list()
                if isFixed:
                        partflags.append("FIXED")
                if isMaster:
                        partflags.append("MASTER")
                if isKey:
                        partflags.append("IDKEY")
                if isCache:
                        partflags.append("CACHE")
                if isData:
                        partflags.append("DATA")
                if isSecure:
                        partflags.append("SECURED")
                if isErase:
                        partflags.append("ERASE")
                print "File Version: \t\t %s"%partsw
                print "Partition in use: \t %s"%bool(partIsUsed)
                print "Partition Flags: \t %s" %",".join(partflags)
