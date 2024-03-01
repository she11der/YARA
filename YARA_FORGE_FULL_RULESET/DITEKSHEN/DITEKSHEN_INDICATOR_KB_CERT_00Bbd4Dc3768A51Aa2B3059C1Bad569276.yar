import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Bbd4Dc3768A51Aa2B3059C1Bad569276 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "cb5214b4-1af5-5b31-b690-6531139e92b1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4509-L4520"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "d506c2d6e630fabe1d4b805cd31aa54b04959db80630f656b3460c869ad544fa"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "36936c4aa401c3bbeb227ce5011ec3bdc02fdd14"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JJ ELECTRICAL SERVICES LIMITED" and pe.signatures[i].serial=="00:bb:d4:dc:37:68:a5:1a:a2:b3:05:9c:1b:ad:56:92:76")
}
