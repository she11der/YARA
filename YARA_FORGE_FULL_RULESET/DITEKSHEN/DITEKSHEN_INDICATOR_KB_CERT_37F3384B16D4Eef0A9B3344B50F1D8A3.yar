import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_37F3384B16D4Eef0A9B3344B50F1D8A3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a7eef803-2c9e-5f23-acde-22ae2223fec2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4591-L4602"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "4496052ff9677e0d031471e4ae9b3541099a2dbe024b4b5ba3f757800bfdcb07"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3fcdcf15c35ef74dc48e1573ad1170b11a623b40"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sore Loser Games ApS" and pe.signatures[i].serial=="37:f3:38:4b:16:d4:ee:f0:a9:b3:34:4b:50:f1:d8:a3")
}
