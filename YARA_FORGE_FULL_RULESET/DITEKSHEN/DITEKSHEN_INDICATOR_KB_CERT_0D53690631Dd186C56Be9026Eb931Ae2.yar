import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0D53690631Dd186C56Be9026Eb931Ae2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "f0afbdf4-68db-522f-95d7-cd76aa7b9710"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L42-L53"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "645c2340fe7e7ce992f3f655d5058834d0df6a64ea20ef7794893a592124c55e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c5d1e46a40a8200587d067814adf0bbfa09780f5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STA-R TOV" and pe.signatures[i].serial=="0d:53:69:06:31:dd:18:6c:56:be:90:26:eb:93:1a:e2")
}
