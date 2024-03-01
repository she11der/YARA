import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_C81319D20C6F1F1Aec3398522189D90C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d93f571b-49f6-5a8b-9478-1054ede2257f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8476-L8489"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1271d0cc05d35a70a90f605e7c68fc52605570e453e9e67fbeb74762a88a0a96"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "18d8be8afa6613e2ef037598a6e08e0ef197d420f21aa4050f473fcabd16644a"
		reason = "RedLineStealer"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and pe.signatures[i].serial=="c8:13:19:d2:0c:6f:1f:1a:ec:33:98:52:21:89:d9:0c")
}
