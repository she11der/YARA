import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3972443Af922B751D7D36C10Dd313595 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "21ada866-167a-54d5-a137-7720de32520e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4578-L4589"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "764d0a288edd3bac90c0b93319f4f8ff8a7d567cda42aa52fe6114f4e56216ad"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d89e3bd43d5d909b47a18977aa9d5ce36cee184c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sore Loser Games ApS" and pe.signatures[i].serial=="39:72:44:3a:f9:22:b7:51:d7:d3:6c:10:dd:31:35:95")
}
