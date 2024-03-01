import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_040Cc2255Db4E48Da1B4F242F5Edfa73 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4673a61f-1c2b-5f92-af28-d55b5d913784"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2105-L2116"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "ade204ebb2bf26515984d20ae459aaea56136acfd37a54abc794969fd05c54ce"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1270a79829806834146ef50a8036cfcc1067e0822e400f81073413a60aa9ed54"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Softland SRL" and pe.signatures[i].serial=="04:0c:c2:25:5d:b4:e4:8d:a1:b4:f2:42:f5:ed:fa:73")
}
