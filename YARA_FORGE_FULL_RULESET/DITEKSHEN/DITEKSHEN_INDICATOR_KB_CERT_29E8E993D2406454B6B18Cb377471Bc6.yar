import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_29E8E993D2406454B6B18Cb377471Bc6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a80f015c-3793-52ac-a405-1a7fe2ca0caa"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7728-L7739"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "bf248e664d00675d3fc87070b6358ca7539ef6e748b8bfafcba7ecb91cb1ea05"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0fb38235366b0ba534a6f81c02d9a67555235e07"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MONDIAL MONTERO SP Z O O" and pe.signatures[i].serial=="29:e8:e9:93:d2:40:64:54:b6:b1:8c:b3:77:47:1b:c6")
}
