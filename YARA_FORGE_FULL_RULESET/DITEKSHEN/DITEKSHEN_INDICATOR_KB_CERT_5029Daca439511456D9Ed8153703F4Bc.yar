import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5029Daca439511456D9Ed8153703F4Bc : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "1d7f0d61-fbe7-58d1-a9d8-083678e8b9bd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L588-L599"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "256b4bebbe4567de9e7d1938dd99f7f9fa13749de2f331aec0bc15f4ab5ab488"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9d5ded35ffd34aa78273f0ebd4d6fa1e5337ac2b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE GREEN PARTNERSHIP LTD" and pe.signatures[i].serial=="50:29:da:ca:43:95:11:45:6d:9e:d8:15:37:03:f4:bc")
}
