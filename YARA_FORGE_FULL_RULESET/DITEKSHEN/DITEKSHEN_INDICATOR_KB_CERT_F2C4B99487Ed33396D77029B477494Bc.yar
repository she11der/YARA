import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_F2C4B99487Ed33396D77029B477494Bc : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "594a5def-2516-5639-a72b-9b84b65de1e0"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1715-L1726"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "109d71674b652a2f42bb2a45c877d3a6cbfe280d0324f9ac8fa746d322440694"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f38abffd259919d68969b8b2d265afac503a53dd"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bedaabaefadfdfedcbbbebaaef" and pe.signatures[i].serial=="f2:c4:b9:94:87:ed:33:39:6d:77:02:9b:47:74:94:bc")
}
