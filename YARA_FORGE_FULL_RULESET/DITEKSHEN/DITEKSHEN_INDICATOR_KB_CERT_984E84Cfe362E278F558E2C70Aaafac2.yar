import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_984E84Cfe362E278F558E2C70Aaafac2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3d071d42-b96a-5491-96f5-4605b6b5584e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8881-L8894"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a3a42c5b6ad094deb2a9f33789b6f7e52f76e65b2336372341f16389cef40f88"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0b2d1dad72c69644f80ad871743878b5eb1e45e451d0d2c9579bdf81384f8727"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Arctic Nights Äkäslompolo Oy" and pe.signatures[i].serial=="98:4e:84:cf:e3:62:e2:78:f5:58:e2:c7:0a:aa:fa:c2")
}
