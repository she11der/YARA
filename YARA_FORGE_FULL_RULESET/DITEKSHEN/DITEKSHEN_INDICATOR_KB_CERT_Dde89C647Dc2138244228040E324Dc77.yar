import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Dde89C647Dc2138244228040E324Dc77 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5008d334-964a-516b-895e-761ae94e5bd4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5419-L5430"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "d6c11a277f855ad8a4b235e1461ad024c4490d04530b91ecb47c8fcf8dee1239"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1d9aaa1bc7d6fc5a76295dd1cf692fe4a1283f04"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WMade by H5et.com" and pe.signatures[i].serial=="dd:e8:9c:64:7d:c2:13:82:44:22:80:40:e3:24:dc:77")
}
