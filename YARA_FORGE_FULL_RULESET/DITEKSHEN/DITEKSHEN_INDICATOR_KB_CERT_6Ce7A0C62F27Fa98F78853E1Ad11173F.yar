import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6Ce7A0C62F27Fa98F78853E1Ad11173F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "dd6ba685-deac-5ba0-8268-2ff17f3efc5a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7030-L7041"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "48692213d57293d28d0eb146d24036fa7e7357e55df07330d596a51a0665f063"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "638dc7cd59f1d634c19e4fc2c41b38ae08a1d2e5"
		importance = 20

	condition:
		( uint16(0)==0x5a4d or uint32(0)==0xe011cfd0) and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "D&K ENGINEERING" and pe.signatures[i].serial=="6c:e7:a0:c6:2f:27:fa:98:f7:88:53:e1:ad:11:17:3f")
}
