import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D9E834182Dec62C654E775E809Ac1D1B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ce1640b7-6631-5e8f-a2df-0716b2f86b99"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5485-L5497"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		hash = "645dbb6df97018fafb4285dc18ea374c721c86349cb75494c7d63d6a6afc27e6"
		logic_hash = "3e7ca9aec19f118c7a143826838244f3f8d0a603a44980522f5227a9c3a82a88"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5bb983693823dbefa292c86d93b92a49ec6f9b26"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FoodLehto Oy" and pe.signatures[i].serial=="00:d9:e8:34:18:2d:ec:62:c6:54:e7:75:e8:09:ac:1d:1b")
}
