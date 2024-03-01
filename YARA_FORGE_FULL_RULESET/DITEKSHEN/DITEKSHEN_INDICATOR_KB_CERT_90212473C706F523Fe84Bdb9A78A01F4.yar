import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_90212473C706F523Fe84Bdb9A78A01F4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f195cf1e-4e01-51ec-ae12-21ff56dd58e2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7801-L7814"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8cd1e984bb81f071053614ae9d037d7ff5e01fb95aaa0474492386a7b5faecec"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6b18e9451c2e93564ed255e754b7e1cf0f817abda93015b21ae5e247c75f9d03"
		reason = "Cerber"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DEMUS, OOO" and pe.signatures[i].serial=="90:21:24:73:c7:06:f5:23:fe:84:bd:b9:a7:8a:01:f4")
}
