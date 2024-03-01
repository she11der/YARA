import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1Ef6392B2993A6F67578299659467Ea8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f5539ca9-d5cc-538e-8e53-3274791bfa2b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7501-L7513"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "eabfeb7abc968188276ba76cd94bd80aba340f5f920881fe13c0f7b093d65a55"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e87d3e289ccb9f8f9caa53f2aefba102fbf4b231"
		hash1 = "8282e30e3013280878598418b2b274cadc5e00febaa2b93cf25bb438ee6eb032"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALUSEN d. o. o." and pe.signatures[i].serial=="1e:f6:39:2b:29:93:a6:f6:75:78:29:96:59:46:7e:a8")
}
