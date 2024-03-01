import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0B5759Bc22Ad2128B8792E8535F9161E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c35c4e07-73d9-54d6-a8cb-1558502a82e9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3386-L3397"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1ee543c204e5bf004224a2010f8cfd3196bb9c1e96de350548403224eaa502f6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ddfd6a93a8d33f0797d5fdfdb9abf2b66e64350a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ceeacfeacafdcdffabdbbacf" and pe.signatures[i].serial=="0b:57:59:bc:22:ad:21:28:b8:79:2e:85:35:f9:16:1e")
}
