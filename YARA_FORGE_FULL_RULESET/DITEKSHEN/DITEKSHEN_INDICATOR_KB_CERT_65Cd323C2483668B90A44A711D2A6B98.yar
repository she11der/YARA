import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_65Cd323C2483668B90A44A711D2A6B98 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b976e930-cf9a-5b0f-9a1b-c35c3f134bdd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4166-L4177"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "e0a9868f9a42aeb8f90aff540a73bc8fa1bfebbf8ee6c0c71bd921cf914e0875"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "188810cf106a5f38fe8aa0d494cbd027da9edf97"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Giperion" and pe.signatures[i].serial=="65:cd:32:3c:24:83:66:8b:90:a4:4a:71:1d:2a:6b:98")
}
