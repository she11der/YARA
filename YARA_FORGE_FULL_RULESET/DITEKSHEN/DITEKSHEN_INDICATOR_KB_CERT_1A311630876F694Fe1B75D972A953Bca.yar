import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1A311630876F694Fe1B75D972A953Bca : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2a39397f-1585-5f7f-a2a9-aab62d29a2b2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3841-L3852"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f14532caf49e6f46f75e42e334d3170db0ebebfe75c9f3e057c237691b5d86a2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d473ec0fe212b7847f1a4ee06eff64e2a3b4001e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GTEC s.r.o." and pe.signatures[i].serial=="1a:31:16:30:87:6f:69:4f:e1:b7:5d:97:2a:95:3b:ca")
}
