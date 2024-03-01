import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_64F82Ed8A90F92A940Be2Bb90Fbf6F48 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "70469507-30f1-56be-90bb-1055f7df2496"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2939-L2950"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "eacb9d8834bdf618b5aa44bfb37b0b6413f9b4595b6261a948566a63e9855162"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4d00f5112caf80615852ffe1f4ee72277ed781c3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Klimate Vision Plus" and pe.signatures[i].serial=="64:f8:2e:d8:a9:0f:92:a9:40:be:2b:b9:0f:bf:6f:48")
}
