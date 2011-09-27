/*
 * epk2.h
 *
 *  Created on: 16.02.2011
 *      Author: sirius
 */

#ifndef EPK_H_
#define EPK_H_

#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#include <config.h>



typedef enum {
	BOOT = 0x0,
	MTDI = 0x1,
	CRC3 = 0x2,
	ROOT = 0x3,
	LGIN = 0x4,
	MODE = 0x5,
	KERN = 0x6,
	LGAP = 0x7,
	LGRE = 0x8,
	LGFO = 0x9,
	ADDO = 0xA,
	ECZA = 0xB,
	RECD = 0xC,
	MICO = 0xD,
	SPIB = 0xE,
	SYST = 0xF,
	USER = 0x10,
	NETF = 0x11,
	IDFI = 0x12,
	LOGO = 0x13,
	OPEN = 0x14,
	YWED = 0x15,
	CMND = 0x16,
	NVRA = 0x17,
	PREL = 0x18,
	KIDS = 0x19,
	STOR = 0x1A,
	CERT = 0x1B,
	AUTH = 0x1C,
	ESTR = 0x1D,
	GAME = 0x1E,
	BROW = 0x1F,
	CE_F = 0x20,
	ASIG = 0x21,
	RESE = 0x22,
	BASE = 0x23,
	PATC = 0x24,
	CFGI = 0x25,
	PQLD = 0x26,
	TPLI = 0x27,
	EPAK = 0x41,
	UNKNOWN = 0x42,
} pak_type_t;


#endif /* EPK_H_ */
