import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_016836311Fc39Fbb8E6F308Bb03Cc2B3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "06cc9c38-c5a6-5311-8ceb-943ea3993fc7"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2404-L2415"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "912d490ac5d746c584e4dd5639be98d9577faba215cc1f8ebdf360581be53d5c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "cab373e2d4672beacf4ca9c9baf75a2182a106cca5ea32f2fc2295848771a979"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SERVICE STREAM LIMITED" and pe.signatures[i].serial=="01:68:36:31:1f:c3:9f:bb:8e:6f:30:8b:b0:3c:c2:b3")
}
