import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_028D50Ae0C554B49148E82Db5B1C2699 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "35cd05db-c399-5d37-a191-9170b048e263"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L523-L534"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7fe907059e83a058705a2884d514938c51fd206b0a175cfb9e8619244c20c62f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0abdbc13639c704ff325035439ea9d20b08bc48e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VAS CO PTY LTD" and pe.signatures[i].serial=="02:8d:50:ae:0c:55:4b:49:14:8e:82:db:5b:1c:26:99")
}
