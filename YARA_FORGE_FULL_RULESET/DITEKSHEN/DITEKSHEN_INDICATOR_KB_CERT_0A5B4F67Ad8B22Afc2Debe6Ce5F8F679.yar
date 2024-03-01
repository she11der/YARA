import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0A5B4F67Ad8B22Afc2Debe6Ce5F8F679 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e1cc3d27-4f76-58a8-8dd6-fd8dbe48252e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4153-L4164"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "19cf46c112b546c26f12891727fdbc74aaa78bbdcdbc4e041781394f4cf5f719"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1213865af7ddac1568830748dbdda21498dfb0ba"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Farad LLC" and pe.signatures[i].serial=="0a:5b:4f:67:ad:8b:22:af:c2:de:be:6c:e5:f8:f6:79")
}
