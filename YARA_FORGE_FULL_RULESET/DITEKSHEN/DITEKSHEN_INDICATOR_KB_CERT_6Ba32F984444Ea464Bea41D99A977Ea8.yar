import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6Ba32F984444Ea464Bea41D99A977Ea8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "6fee5b3f-f72e-531e-b11e-e402207072ff"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L980-L991"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "fcabdd038a2594dffddbfff71a7a8a1abae89c637355b3be7e5f26c1eb9e39c7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ae9e65e26275d014a4a8398569af5eeddf7a472c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JIN CONSULTANCY LIMITED" and pe.signatures[i].serial=="6b:a3:2f:98:44:44:ea:46:4b:ea:41:d9:9a:97:7e:a8")
}
