import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D627F1000D12485995514Bfbdefc55D9 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "dd18086c-063b-542e-915b-5bd452ee452e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1832-L1843"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9ff60a73b889c8f1df127ead90a93fbf92131cfb475d58eea1ba1569f3e99e00"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5fac3a6484e93f62686e12de3611f7a5251009d541f65e8fe17decc780148052"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THREE D CORPORATION PTY LTD" and pe.signatures[i].serial=="00:d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9")
}
