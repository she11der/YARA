import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D4Ef1Ab6Ab5D3Cb35E4Efb7984Def7A2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d96df78b-3824-5f94-8a32-87dfd9cd585f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4418-L4429"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "845abc1f08a4d56b32477fbe8855f45633833c68f4255d0690f10cc23c167e84"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "10d82c75a1846ebfb2a0d1abe9c01622bdfabf0a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REIGN BROS ApS" and pe.signatures[i].serial=="00:d4:ef:1a:b6:ab:5d:3c:b3:5e:4e:fb:79:84:de:f7:a2")
}
