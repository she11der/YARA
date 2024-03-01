import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Dummy01 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "eaf3bbdd-72b4-513c-9a5b-04f16292fa00"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4673-L4687"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "c72ac977ef92feead0a7ec72ec99b1a11f20b8c5258a08842a4dceddff91d659"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint1 = "16b7eb40b97149f49e8ec885b0a7fa7598f5a00f"
		thumbprint2 = "902bf957b57f134619443d80cb8767250e034110"
		thumbprint3 = "505f0055a66216c81420f41335ea7a4eb7b240fe"
		thumbprint4 = "c05a6806d770dcec780e0477b83f068a1082be06"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dummy certificate" and pe.signatures[i].serial=="01")
}
