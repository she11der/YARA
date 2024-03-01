import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_141D6Dafed065980D97520E666493396 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1a2e44d7-b801-5c3e-bf74-616f211c6d93"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2586-L2597"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "37ed05b7a472ec6cbc1bba453f3be9ca1bd590ed6470d6607873ef52b28e3ea5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "28225705d615a47de0d1b0e324b5b9ca7c11ce48"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ralph Schmidt" and pe.signatures[i].serial=="14:1d:6d:af:ed:06:59:80:d9:75:20:e6:66:49:33:96")
}
