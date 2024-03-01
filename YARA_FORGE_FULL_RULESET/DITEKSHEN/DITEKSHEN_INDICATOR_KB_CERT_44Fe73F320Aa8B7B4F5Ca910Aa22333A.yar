import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_44Fe73F320Aa8B7B4F5Ca910Aa22333A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "fb7a2f49-d5b4-59af-b64b-27624ff18323"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6457-L6468"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a456cd32eed6c1f037bc565e7a43f2a5a2237749afc31f6b7a8b8d7a657973c6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e952eb51416ab15c0a38b64a32348ed40b675043"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Alpeks LLC" and pe.signatures[i].serial=="44:fe:73:f3:20:aa:8b:7b:4f:5c:a9:10:aa:22:33:3a")
}
