import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_84C3A47B739F1835D35B755D1E6741B5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "00fba5a5-b87d-54f7-a5b8-f7b377af2202"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2991-L3002"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6beb0966f2ed981c2e1a859ff9f659a566de867888123c387eeb89a97620345e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8057f20f9f385858416ec3c0bd77394eff595b69"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bddbdcfabededdeadbefed" and pe.signatures[i].serial=="84:c3:a4:7b:73:9f:18:35:d3:5b:75:5d:1e:67:41:b5")
}
