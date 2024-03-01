import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_121Fca3Cfa4Bd011669F5Cc4E053Aa3F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "be18fe1a-f810-5153-b565-97a0e33cf406"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3542-L3553"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "c5f7f23d9ba35bed3540233217e18b84c5ac0528fd3fe809c162fce6ccce0791"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "84b5ef4f981020df2385754ab1296821fa2f8977"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kymijoen Projektipalvelut Oy" and pe.signatures[i].serial=="12:1f:ca:3c:fa:4b:d0:11:66:9f:5c:c4:e0:53:aa:3f")
}
