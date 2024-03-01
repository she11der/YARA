import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2888Cf0F953A4A3640Ee4Cfc6304D9D4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4c3153e4-d3ce-5e87-8e72-969cba972e26"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3815-L3826"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5e0d1b74422ae1004b0054c161d1dc949bb368ac17575e33c9b6d550bb136126"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "eb5f5ab7294ba39f2b77085f47382bd7e759ff3a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lotte Schmidt" and pe.signatures[i].serial=="28:88:cf:0f:95:3a:4a:36:40:ee:4c:fc:63:04:d9:d4")
}
