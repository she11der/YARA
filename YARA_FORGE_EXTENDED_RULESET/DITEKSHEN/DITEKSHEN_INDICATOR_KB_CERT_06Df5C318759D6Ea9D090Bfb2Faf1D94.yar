import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_06Df5C318759D6Ea9D090Bfb2Faf1D94 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8c1f226f-6fc0-5136-ac19-7d88d7505a8e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7322-L7334"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "3be08901a44c1c94cfb93e56075270ed974399ccc0a4dce15299456dad645822"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4418e9a7aab0909fa611985804416b1aaf41e175"
		hash1 = "47dbb2594cd5eb7015ef08b7fb803cd5adc1a1fbe4849dc847c0940f1ccace35"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SpiffyTech Inc." and pe.signatures[i].serial=="06:df:5c:31:87:59:d6:ea:9d:09:0b:fb:2f:af:1d:94")
}
