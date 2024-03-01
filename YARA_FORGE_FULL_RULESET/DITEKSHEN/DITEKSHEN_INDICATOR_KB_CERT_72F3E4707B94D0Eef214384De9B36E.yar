import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_72F3E4707B94D0Eef214384De9B36E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "bf02ea89-b3f3-58a1-8bcd-1a23b3c96b68"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3464-L3475"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "c2a310ff70012076856239b5b5e6b46ffa121479dea38815e61f5336cecf8868"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e2a5a2823b0a56c88bfcb2788aa4406e084c4c9b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eaaebecedccfd" and pe.signatures[i].serial=="72:f3:e4:70:7b:94:d0:ee:f2:14:38:4d:e9:b3:6e")
}
