import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_58Ec8821Aa2A3755E1075F73321756F4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "efa0e5c6-773a-5740-b7f9-ec10a92b1623"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3893-L3904"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b79f161c77cbae0bec55fb2b047983660c84d2bb93db8c91cb6c22fd4ad197cc"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "19dd0d7f2edf32ea285577e00dd13c966844cfa4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cbebbfeaddcbcccffdcdc" and pe.signatures[i].serial=="58:ec:88:21:aa:2a:37:55:e1:07:5f:73:32:17:56:f4")
}
