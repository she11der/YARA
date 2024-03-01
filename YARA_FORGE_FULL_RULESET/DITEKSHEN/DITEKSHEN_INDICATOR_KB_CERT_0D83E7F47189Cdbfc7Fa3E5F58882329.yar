import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0D83E7F47189Cdbfc7Fa3E5F58882329 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "6574aab4-f307-53c2-8cf7-bcc7565facc8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4621-L4632"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "c4dffcad286e161980ccec2188459b8b7eaf0e982c7c69ca5ffbaf8e4d85d1b4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ba4bf6d8caac468c92dd7cd4303cbdb2c9f58886"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and pe.signatures[i].serial=="0d:83:e7:f4:71:89:cd:bf:c7:fa:3e:5f:58:88:23:29")
}
