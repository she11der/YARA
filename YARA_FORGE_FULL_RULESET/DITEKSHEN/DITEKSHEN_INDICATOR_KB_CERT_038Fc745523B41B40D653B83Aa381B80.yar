import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_038Fc745523B41B40D653B83Aa381B80 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ed7581eb-52e7-5216-86a2-079bc5741b05"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4901-L4912"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b760525c38610b8a5cc990335122eab81cb895dc523908ef841c5c3117a1a372"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "05124a4a385b4b2d7a9b58d1c3ad7f2a84e7b0af"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Optima" and pe.signatures[i].serial=="03:8f:c7:45:52:3b:41:b4:0d:65:3b:83:aa:38:1b:80")
}
