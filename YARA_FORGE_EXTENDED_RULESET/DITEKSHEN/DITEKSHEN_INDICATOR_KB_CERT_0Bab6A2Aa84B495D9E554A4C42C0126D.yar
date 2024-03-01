import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Bab6A2Aa84B495D9E554A4C42C0126D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "be364465-0cab-59cd-82a2-b7b16f260f34"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L406-L417"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a9ecdf1107cba0767ac3fa52c7dd65a13015e4fd735da70b6f1e6dbcfe2f7526"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "230614366ddac05c9120a852058c24fa89972535"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NOSOV SP Z O O" and pe.signatures[i].serial=="0b:ab:6a:2a:a8:4b:49:5d:9e:55:4a:4c:42:c0:12:6d")
}
