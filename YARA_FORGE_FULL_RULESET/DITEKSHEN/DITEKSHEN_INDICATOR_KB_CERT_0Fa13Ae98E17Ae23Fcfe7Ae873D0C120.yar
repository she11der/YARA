import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Fa13Ae98E17Ae23Fcfe7Ae873D0C120 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5e926cb1-efd0-5f9d-9327-341bb2f1a5f5"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2014-L2025"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "312d810386aebb509ffbd09d6b1ad6a761a03bc07ba5e4a158235786063389a9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "be226576c113cd14bcdb67e46aab235d9257cd77b826b0d22a9aa0985bad5f35"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KLAKSON, LLC" and pe.signatures[i].serial=="0f:a1:3a:e9:8e:17:ae:23:fc:fe:7a:e8:73:d0:c1:20")
}
