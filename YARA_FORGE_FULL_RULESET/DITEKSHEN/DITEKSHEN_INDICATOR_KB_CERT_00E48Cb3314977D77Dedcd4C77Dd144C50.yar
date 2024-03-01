import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E48Cb3314977D77Dedcd4C77Dd144C50 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9b708e1b-a878-5244-8fe2-3061f058a9ab"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2144-L2155"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a2ca0ce3812be5e46cb0bc9c73fc4f31294c8d594ca821ad924a3f06cf2430ca"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "025bce0f36ec5bac08853966270ed2f5e28765d9c398044462a28c67d74d71e1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BESPOKE SOFTWARE SOLUTIONS LIMITED" and pe.signatures[i].serial=="00:e4:8c:b3:31:49:77:d7:7d:ed:cd:4c:77:dd:14:4c:50")
}
