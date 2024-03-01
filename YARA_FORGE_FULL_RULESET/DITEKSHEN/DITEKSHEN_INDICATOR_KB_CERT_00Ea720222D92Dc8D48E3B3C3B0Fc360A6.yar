import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ea720222D92Dc8D48E3B3C3B0Fc360A6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2e43e98a-61f8-5f93-a415-52cb6453620d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3867-L3878"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "97b2699d4cb0fd88e3440ea82dd6ea87cdac69c6ba2acd884f5aef577b55e79d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "522d0f1ca87ef784994dfd63cb0919722dfdb79f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CAVANAGH NETS LIMITED" and pe.signatures[i].serial=="00:ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6")
}
