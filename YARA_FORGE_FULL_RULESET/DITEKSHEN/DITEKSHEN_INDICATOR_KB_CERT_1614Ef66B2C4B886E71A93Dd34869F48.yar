import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1614Ef66B2C4B886E71A93Dd34869F48 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "27bead15-f7fa-55a1-9347-ea551e1e0e18"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7936-L7949"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "26265d54d8b58128c1a9a3b322f339d1beb438f403637519b11ff324af91d1e2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1689697e08dda6d1233c0056078ddf25b12c3608ead7d96ed4cbbb074e54ce29"
		reason = "RemcosRAT"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SHIRT AND CUFF LIMITED" and pe.signatures[i].serial=="16:14:ef:66:b2:c4:b8:86:e7:1a:93:dd:34:86:9f:48")
}
