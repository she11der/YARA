import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_13039Da3B2924B7A8B0A2Ac4637C2Efa : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9621584b-a115-5b96-8de5-15776232cdb2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4431-L4442"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7492f2a50effae809b512ce7a2a769f3db62ab3573974206b729417cc629ca83"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ad9fa264674c152b2298533e41e098bcaa0345af"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Tekhnokom" and pe.signatures[i].serial=="13:03:9d:a3:b2:92:4b:7a:8b:0a:2a:c4:63:7c:2e:fa")
}
