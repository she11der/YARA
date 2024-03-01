import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Aa099E64E214D655801Ea38Ad876711 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "00b9cd1f-e389-51fd-8a08-73334bb0d0ef"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6700-L6712"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a4211bc2f3cedb8b135566d4b22251523a3a2bbdb04c1f1c5b1336ae7c198773"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0789b35fd5c2ef8142e6aae3b58fff14e4f13136"
		hash1 = "9f90e6711618a1eab9147f90bdedd606fd975b785915ae37e50e7d2538682579"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Psiphon Inc." and pe.signatures[i].serial=="0a:a0:99:e6:4e:21:4d:65:58:01:ea:38:ad:87:67:11")
}
