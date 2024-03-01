import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_8035Ed9C58Ea895505B05Ff926D486Bc : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "35b5d9a1-eaa8-53d8-9917-9a688fb95a04"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3108-L3119"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "caf1c962a0f4bd6c90753c6f1f0a2acadafa5fde6c7dacd02a3ca5cc15446ab4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b82a7f87b7d7ccea50bba5fe8d8c1c745ebcb916"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fecddacdddfaadcddcabceded" and pe.signatures[i].serial=="80:35:ed:9c:58:ea:89:55:05:b0:5f:f9:26:d4:86:bc")
}
