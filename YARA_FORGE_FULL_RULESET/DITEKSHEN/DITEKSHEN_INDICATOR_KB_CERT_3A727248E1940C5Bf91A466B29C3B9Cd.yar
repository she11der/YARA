import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3A727248E1940C5Bf91A466B29C3B9Cd : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "db43ed73-de46-526e-a255-137a4eaaedce"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1153-L1164"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0afeb50b36d0ca1adbd6cb3accccb3ee093434b8c0bd8b03ae70ecc45c7423b5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "eeeb3a616bb50138f84fc0561d883b47ac1d3d3d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\x90\\x89\\xE5\\x90\\x89\\xD0\\x98\\xE5\\x90\\x89\\xD0\\x98\\xE4\\xB8\\x9D\\xE4\\xB8\\x9D" and pe.signatures[i].serial=="3a:72:72:48:e1:94:0c:5b:f9:1a:46:6b:29:c3:b9:cd")
}
