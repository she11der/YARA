import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_02De1Cc6C487954592F1Bf574Ca2B000 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1dc1b576-34f4-5017-8340-c6f58692a31c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5165-L5176"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5963377fee755a859bc4330a1094ea1c8b2b588133706a22f67c1fb85542e64f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e35804bbf4573f492c51a7ad7a14557816fe961f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Orca System" and pe.signatures[i].serial=="02:de:1c:c6:c4:87:95:45:92:f1:bf:57:4c:a2:b0:00")
}
