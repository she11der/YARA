import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D1737E5A94D2Aff121163Df177Ed7Cf7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "92ba22ba-9610-5b9b-9075-1da84fb148c1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7000-L7015"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7889e42ca0bc6c4aad0c7cf90459958e9d256b984fae719bd418fc17120cb4a2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ed2e4f72e8cb9b008a28b31de440f024381e4c8d"
		hash1 = "66dfb7c408d734edc2967d50244babae27e4268ea93aa0daa5e6bbace607024c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BedstSammen ApS" and (pe.signatures[i].serial=="d1:73:7e:5a:94:d2:af:f1:21:16:3d:f1:77:ed:7c:f7" or pe.signatures[i].serial=="00:d1:73:7e:5a:94:d2:af:f1:21:16:3d:f1:77:ed:7c:f7"))
}
