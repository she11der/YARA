import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_C2Cbbd946Bc3Fdb944D522931D61D51A : FILE
{
	meta:
		description = "Detects executables signed with Sordum Software certificate, particularly Defender Control"
		author = "ditekSHen"
		id = "b8ccfb1a-4e3f-5823-af38-e1607458023e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4231-L4242"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6e67835cf85c713ef5a21b866a277e90236c607fb67d3fd9b2bba627c31d9e97"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f5e71628a478a248353bf0177395223d2c5a0e43"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sordum Software" and pe.signatures[i].serial=="c2:cb:bd:94:6b:c3:fd:b9:44:d5:22:93:1d:61:d5:1a")
}
