import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5B440A47E8Ce3Dd202271E5C7A666C78 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "62c9a37c-e4dd-5925-a019-08bf6a77476d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2053-L2064"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f898a3495e173d85fd62598da87ab15cbee0674519231a5e770204a4db3cd93f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "07e4cbdd52027e38b86727e88b33a0a1d49fe18f5aee4101353dd371d7a28da5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Master Networking s.r.o." and pe.signatures[i].serial=="5b:44:0a:47:e8:ce:3d:d2:02:27:1e:5c:7a:66:6c:78")
}
