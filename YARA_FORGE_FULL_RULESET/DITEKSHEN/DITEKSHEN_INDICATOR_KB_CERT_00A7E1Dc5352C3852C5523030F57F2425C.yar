import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00A7E1Dc5352C3852C5523030F57F2425C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "fba8f1a8-ca08-5d6f-a83e-c817daf94703"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4689-L4700"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "06c151ae8b4a45eccef028ea69f0adf74445bd4d871fc65cc1d308f2005cede1"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "09232474b95fc2cfb07137e1ada82de63ffe6fcd"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pushka LLC" and pe.signatures[i].serial=="00:a7:e1:dc:53:52:c3:85:2c:55:23:03:0f:57:f2:42:5c")
}
