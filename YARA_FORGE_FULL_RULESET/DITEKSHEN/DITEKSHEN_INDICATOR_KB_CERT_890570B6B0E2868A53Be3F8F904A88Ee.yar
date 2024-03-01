import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_890570B6B0E2868A53Be3F8F904A88Ee : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8d619117-00cb-5276-87c1-3f6cd701218d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8146-L8159"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "952b211cc2c7988b9a09ca5a96c44fea24bbaced28a79ab0ae6732675fda7365"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f291d21d72dcefc369526a97b7d39214544b22057757ac00907ab4ff3baa2edd"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JESEN LESS d.o.o." and pe.signatures[i].serial=="89:05:70:b6:b0:e2:86:8a:53:be:3f:8f:90:4a:88:ee")
}
