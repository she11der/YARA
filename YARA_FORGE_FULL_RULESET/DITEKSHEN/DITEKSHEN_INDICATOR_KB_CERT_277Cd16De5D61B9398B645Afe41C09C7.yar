import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_277Cd16De5D61B9398B645Afe41C09C7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d5ada3bf-322a-5794-aff7-75ff8dd9a7d1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6392-L6403"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "dccfd52a3bcc11897d05f5450600dbd2f1f699732341cebed6dda37a76fd5f2d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "11a18b9ba48e2b715202def00c2005a394786b23"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE SIGN COMPANY LIMITED" and pe.signatures[i].serial=="27:7c:d1:6d:e5:d6:1b:93:98:b6:45:af:e4:1c:09:c7")
}
