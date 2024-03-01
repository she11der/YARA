import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Ca5Acafb5Fdca6F8B5D66D1339A5D85 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "6f0e9e3a-52fc-5ffd-90b3-743d925388df"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7267-L7279"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2612e58b4e1a6fa65b32fe855b3542882c79345e93ab134933c893e90bb1a75c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ab25053a3f739ddd4505cf5d9d33b5cc50f3ab35"
		hash1 = "a3ab41d9642a5a5aa6aa4fc1e316970e06fa26c6c545dd8ff56f82f41465ec08"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Valve" and pe.signatures[i].serial=="0c:a5:ac:af:b5:fd:ca:6f:8b:5d:66:d1:33:9a:5d:85")
}
