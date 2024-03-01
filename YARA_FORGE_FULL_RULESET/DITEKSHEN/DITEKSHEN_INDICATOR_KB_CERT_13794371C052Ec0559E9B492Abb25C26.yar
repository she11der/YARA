import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_13794371C052Ec0559E9B492Abb25C26 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e2a4fdb2-fa04-5662-bb84-5c0c4892e3af"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1923-L1934"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "af80177181efd92b4e1a4a5c665df01add069dc3b47074bcbdd503516cf5a844"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "dd3ab539932e81db45cf262d44868e1f0f88a7b0baf682fb89d1a3fcfba3980b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Carmel group LLC" and pe.signatures[i].serial=="13:79:43:71:c0:52:ec:05:59:e9:b4:92:ab:b2:5c:26")
}
