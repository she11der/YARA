import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7D08A74747557D6016Aaaf47A679312F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "031cf958-1c37-5190-8fbd-6896f1048c9a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3334-L3345"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "ff7c9635b9b43bef7401861d5dbf984d1e2aa1ea9e4d3df9ad348c552767628e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d7fdad88c626b8e6d076f3f414bbae353f444618"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Abfacfbdcd" and pe.signatures[i].serial=="7d:08:a7:47:47:55:7d:60:16:aa:af:47:a6:79:31:2f")
}
