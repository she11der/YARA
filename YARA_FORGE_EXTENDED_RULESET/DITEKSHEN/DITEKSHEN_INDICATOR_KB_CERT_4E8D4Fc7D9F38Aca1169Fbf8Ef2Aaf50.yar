import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4E8D4Fc7D9F38Aca1169Fbf8Ef2Aaf50 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "03a23987-bbec-5072-bea4-56773bdc7d53"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L315-L326"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2b440d21183745ac89de56f5ca22cf3f01be3212e20ce80fa67a45adbb6b16fe"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7239764d40118fc1574a0af77a34e369971ddf6d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "INFINITE PROGRAMMING LIMITED" and pe.signatures[i].serial=="4e:8d:4f:c7:d9:f3:8a:ca:11:69:fb:f8:ef:2a:af:50")
}
