import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D4F9Fc08895654F8Bde8D1Cc26Eff015 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d32f82a7-36dd-555f-87cf-28e520a3916f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5789-L5800"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "dfc90ce9c1d8a0fad9c50f61c90c4f7b00b6890ee45d218417f4a7196c3d1c18"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f24af3a784c2316b42854c5853b53d9e556295f7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "kfbdAfVnDMDc" and pe.signatures[i].serial=="00:d4:f9:fc:08:89:56:54:f8:bd:e8:d1:cc:26:ef:f0:15")
}
