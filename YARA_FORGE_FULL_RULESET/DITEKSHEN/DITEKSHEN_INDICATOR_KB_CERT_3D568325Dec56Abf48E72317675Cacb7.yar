import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3D568325Dec56Abf48E72317675Cacb7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "e958b9c4-2f1b-5b5d-8a44-7393204a6f41"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1099-L1110"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a575c9989a3ee7824e8734940877ddb255b19070def460508f70d32f457411ac"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e5b21024907c9115dafccc3d4f66982c7d5641bc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Virtual Byte F-B-I" and pe.signatures[i].serial=="3d:56:83:25:de:c5:6a:bf:48:e7:23:17:67:5c:ac:b7")
}
