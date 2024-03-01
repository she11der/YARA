import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Eb95A7Bd7553533D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b9198469-4eba-552d-a8f5-5841893ff85e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6159-L6170"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "e646346d94791c2a86a7240d4cf1f9138a30ca583b021ae5b17471cef20a98de"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8d658fd671fa097c3db18906a29e8c1fa45113d9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\x02C\\x02\\x97\\x04\\x17\\x04\\x1e\\x04.\\x02\\x90\\x00g\\x02\\x94\\x02\\xae\\x00p\\x04 \\x00K\\x04J\\x02\\x88\\x042\\x02K\\x02\\xa3" and pe.signatures[i].serial=="eb:95:a7:bd:75:53:53:3d")
}
