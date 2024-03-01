import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5D5D03Edb4Ec4E185Caa3041824Ab75C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e1c93911-5c7c-5fe8-aed3-014a9bb7379e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3425-L3436"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "863a1496ce37449fa7e94c407ce0e63a9d727fef9094135715d0cb14ed442e5e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f6c9c564badc1bbd8a804c5e20ab1a0eff89d4c0"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ffcdcbacfeaedbfbcecccafeb" and pe.signatures[i].serial=="5d:5d:03:ed:b4:ec:4e:18:5c:aa:30:41:82:4a:b7:5c")
}
