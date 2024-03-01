import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_77550Ed697992B397E3F1Ad8E2A662D1 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1d969340-de5e-569e-bfed-a80a1623d1b4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8491-L8504"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "87a70f10a111c4c5d1c3fb5b1c2a9da528f7d484ae6391c91e4052aba5c6bbe0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0c439c7b60714158f62c45921caf30d17dae37ec6cbc2dfdd9d306e18ae6df63"
		reason = "ParallaxRAT"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GRASS RAIN, s.r.o." and pe.signatures[i].serial=="77:55:0e:d6:97:99:2b:39:7e:3f:1a:d8:e2:a6:62:d1")
}
