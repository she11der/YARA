import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ac0A7B9420B369Af3Ddb748385B981 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0935fd31-3d8f-57d2-a00e-ad7d5cdbe12d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4914-L4925"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "47dca0d0b84dd0d210cf7fdda3bcce796d090e5de3f4266bbed01eebdd397bfa"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "15b56f8b0b22dbc7c08c00d47ee06b04fa7df5fe"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Tochka" and pe.signatures[i].serial=="00:ac:0a:7b:94:20:b3:69:af:3d:db:74:83:85:b9:81")
}
