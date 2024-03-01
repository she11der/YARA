import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_02E44D7D1D38Ae223B27A02Bacd79B53 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7f2ad143-c46b-58cb-9fe5-c7bb9c6d9234"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4010-L4021"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7ab506b2e4a716bc6f7115a071f46df4ea4ac88a4b636506a13ac0d383664e58"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "34e0ecae125302d5b1c4a7412dbf17bdc1b59f04"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Zhuhai Kingsoft Office Software Co., Ltd." and pe.signatures[i].serial=="02:e4:4d:7d:1d:38:ae:22:3b:27:a0:2b:ac:d7:9b:53")
}
