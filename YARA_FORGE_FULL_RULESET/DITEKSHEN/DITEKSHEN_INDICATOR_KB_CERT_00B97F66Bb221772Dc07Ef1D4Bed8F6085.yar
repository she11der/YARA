import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B97F66Bb221772Dc07Ef1D4Bed8F6085 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c0797751-d03c-59c7-a02a-27e6f466bd96"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5393-L5404"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "e68f6ebbeadc9381c2888abf77e040f27648a40d770524830f8a49fe2d11534f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "fb4efb3bfcef8e9a667c8657f2e3c8fb7436666e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "S-PRO d.o.o." and pe.signatures[i].serial=="00:b9:7f:66:bb:22:17:72:dc:07:ef:1d:4b:ed:8f:60:85")
}
