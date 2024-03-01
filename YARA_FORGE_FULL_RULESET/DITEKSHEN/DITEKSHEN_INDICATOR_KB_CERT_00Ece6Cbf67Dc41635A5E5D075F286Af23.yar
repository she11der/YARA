import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ece6Cbf67Dc41635A5E5D075F286Af23 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "53312007-179d-547c-8195-0b5d78181300"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2443-L2454"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "27ecc138f8d574c15095032c35ad51c00d8b98f21162d1f59f1f9ca9e5b54391"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f1f83c96ab00dcb70c0231d946b6fbd6a01e2c94e8f9f30352bbe50e89a9a51c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THRANE AGENTUR ApS" and pe.signatures[i].serial=="00:ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23")
}
