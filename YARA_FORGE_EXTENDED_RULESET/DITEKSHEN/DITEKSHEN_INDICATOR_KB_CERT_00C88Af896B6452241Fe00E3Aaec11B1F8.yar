import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00C88Af896B6452241Fe00E3Aaec11B1F8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4d73705a-e980-5aa0-a326-e35990226e37"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2716-L2727"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "3a5f290f9479189ff83bf5da3a3d086453c9230311a48f4c0bd4654024ebeef8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9ce1cbf5be77265af2a22e28f8930c2ac5641e12"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TeamViewer Germany GmbH" and pe.signatures[i].serial=="00:c8:8a:f8:96:b6:45:22:41:fe:00:e3:aa:ec:11:b1:f8")
}
