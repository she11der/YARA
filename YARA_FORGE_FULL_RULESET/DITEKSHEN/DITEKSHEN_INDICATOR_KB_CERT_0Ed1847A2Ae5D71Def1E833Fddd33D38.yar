import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Ed1847A2Ae5D71Def1E833Fddd33D38 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "5e09087b-3fd0-5979-8f98-f242231c8b4f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L497-L508"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "2acc6d2262bac8bfe49bb244d62be4dcf626dd9b2c9786b7a8963c48b17e6ab9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e611a7d4cd6bb8650e1e670567ac99d0bf24b3e8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SNAB-RESURS, OOO" and pe.signatures[i].serial=="0e:d1:84:7a:2a:e5:d7:1d:ef:1e:83:3f:dd:d3:3d:38")
}
