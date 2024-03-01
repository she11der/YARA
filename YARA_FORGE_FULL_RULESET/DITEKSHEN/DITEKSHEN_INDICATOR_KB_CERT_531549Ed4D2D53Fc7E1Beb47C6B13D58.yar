import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_531549Ed4D2D53Fc7E1Beb47C6B13D58 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "6aec64ae-cda3-57e8-94c6-07c1e07d34ad"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3095-L3106"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "554574657a913dbe0c576dbfcdd93a2494f2ffccf51eaabf06e5fafe2a895c3a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a8e1f6e32e5342265dd3e28cc65060fb7221c529"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bdabfbdfbcbab" and pe.signatures[i].serial=="53:15:49:ed:4d:2d:53:fc:7e:1b:eb:47:c6:b1:3d:58")
}
