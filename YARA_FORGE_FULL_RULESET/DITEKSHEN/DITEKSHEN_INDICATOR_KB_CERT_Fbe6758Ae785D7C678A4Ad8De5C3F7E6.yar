import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Fbe6758Ae785D7C678A4Ad8De5C3F7E6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4d080acc-fb11-5e4d-9c59-562f30376936"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6242-L6253"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "c6d84435c5c4f71696ce0414c87216bbb0603cb75d6e37abaf73e3708904032e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "bd1958f0306fc8699e829541cd9b8c4fe0e0c6da920932f2cd4d78ed76bda426"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HORUM" and pe.signatures[i].serial=="fb:e6:75:8a:e7:85:d7:c6:78:a4:ad:8d:e5:c3:f7:e6")
}
