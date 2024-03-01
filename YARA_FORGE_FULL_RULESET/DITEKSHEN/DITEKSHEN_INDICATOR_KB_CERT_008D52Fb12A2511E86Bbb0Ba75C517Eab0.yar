import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_008D52Fb12A2511E86Bbb0Ba75C517Eab0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "04b78a1c-bb2c-5844-933b-f95a0cc8c71e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2508-L2519"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "23dc0500af88af0e2c8ea7ff2c5a149d24fb7fd23853c4bf5ee5921a66a34672"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9e918ce337aebb755e23885d928e1a67eca6823934935010e82b561b928df2f9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VThink Software Consulting Inc." and pe.signatures[i].serial=="00:8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0")
}
