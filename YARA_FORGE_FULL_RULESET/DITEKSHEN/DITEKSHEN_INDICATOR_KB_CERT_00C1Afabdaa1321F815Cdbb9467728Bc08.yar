import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00C1Afabdaa1321F815Cdbb9467728Bc08 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "e7904179-672a-5668-8b6d-f7f7090678fb"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1270-L1281"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "be637a192a90a35be9879d5e36fb3cf9a56ca4158329d6b1fad458e2d05e3d26"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e9c5fb9a7d3aba4b49c41b45249ed20c870f5c9e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xD0\\x92\\xD0\\x93\\xE5\\x84\\xBF\\xD0\\x93\\xE5\\x8B\\x92\\xD0\\x92\\xE5\\x8B\\x92\\xD0\\x93\\xD0\\x93\\xE5\\x84\\xBF\\xE8\\x89\\xBE\\xD0\\x92\\xD0\\x93\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xD0\\x92\\xD0\\x93\\xE8\\x89\\xBE\\xE9\\xA9\\xAC\\xD0\\x93\\xE8\\x89\\xBE\\xE9\\xA9\\xAC\\xD0\\x93" and pe.signatures[i].serial=="00:c1:af:ab:da:a1:32:1f:81:5c:db:b9:46:77:28:bc:08")
}
