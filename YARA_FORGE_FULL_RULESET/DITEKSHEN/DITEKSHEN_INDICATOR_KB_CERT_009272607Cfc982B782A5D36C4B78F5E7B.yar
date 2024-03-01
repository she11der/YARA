import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_009272607Cfc982B782A5D36C4B78F5E7B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "dfb01400-dff2-5df1-b38e-7eb2ee2c71b8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1348-L1359"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "d1c2b44e782befc8dae6852935b6f5b0071c13dd9b56857c38cb290c9069df18"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2514c615fe54d511555bc5b57909874e48a438918a54cea4a0b3fbc401afa127"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rada SP Z o o" and pe.signatures[i].serial=="00:92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b")
}
