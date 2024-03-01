import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6000F8C02B0A15B1E53B8399845Faddf : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "6d4224bd-1522-5b0f-b39e-1ba4ec0f1a63"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8806-L8819"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a8687b2aa02909af5fc7c706f31c419c4af48225abe7415bf262de57bb85258f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6f18caa7cd75582d3a311dcc2dadec2ed32e15261c1dc5c9471e213d28367362"
		reason = "Amadey"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAY LIMITED" and pe.signatures[i].serial=="60:00:f8:c0:2b:0a:15:b1:e5:3b:83:99:84:5f:ad:df")
}
