import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_29128A56E7B3Bfb230742591Ac8B4718 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "58a9e9f1-531b-5dee-aa11-1537838e9d3f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2079-L2090"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "16c9843b5e3edafa64e07626fda494452efa5d0bcaa80d7d80683258c2b9acd4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f9fcc798e1fccee123034fe9da9a28283de48ba7ae20f0c55ce0d36ae4625133"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Programavimo paslaugos, MB" and pe.signatures[i].serial=="29:12:8a:56:e7:b3:bf:b2:30:74:25:91:ac:8b:47:18")
}
