import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2Abd2Eef14D480Dfea9Ca9Fdd823Cf03 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5e17d055-26d7-5dde-a905-9d03fb164fa2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4444-L4455"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5f0f5dac599923f385fcd8e8b14349263cabe1c83242fe097d9fb26ea0567c1a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "db3d9ccf11d8b0d4f33cf4dc93689fdd942f8fbe"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BE SOL d.o.o." and pe.signatures[i].serial=="2a:bd:2e:ef:14:d4:80:df:ea:9c:a9:fd:d8:23:cf:03")
}
