import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_121070Be1E782F206985543Bc7Bc58B6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8432c7f0-ee2e-5935-8fe8-36b0094a5e1a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8611-L8624"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "21eb6fed2225d2ab056948603b0990c2eb7dc9289da9a9df16f0d6cd042b3778"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a4534aff03258589a2622398d1904d3bfd264c37e8649a68136f8d552f8b738f"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Prod Can Holdings Inc." and pe.signatures[i].serial=="12:10:70:be:1e:78:2f:20:69:85:54:3b:c7:bc:58:b6")
}
