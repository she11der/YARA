import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_73B60719Ee57974447C68187E49969A2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "c72fb0b8-efdc-5734-9754-2289bd95ae3c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L798-L809"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f9cc0f526a3acbfc30c6b76b6705f1a2d9c905b9bb7c996e4db3ca6d4d63be1c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8e50ddad9fee70441d9eb225b3032de4358718dc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BIT HORIZON LIMITED" and pe.signatures[i].serial=="73:b6:07:19:ee:57:97:44:47:c6:81:87:e4:99:69:a2")
}
