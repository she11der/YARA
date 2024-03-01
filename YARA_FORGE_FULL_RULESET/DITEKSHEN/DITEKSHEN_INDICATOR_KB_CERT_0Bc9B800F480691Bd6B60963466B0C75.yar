import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Bc9B800F480691Bd6B60963466B0C75 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ff76c8b3-8120-54ed-90e1-3ee01e57895e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7114-L7125"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "15143a6dc374f22252880ce61a419df46d81bc1ee99a29d03a61348f9c230064"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8b6c4fc3d54f41ac137795e64477491c93bdf7f1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HasCred ApS" and pe.signatures[i].serial=="0b:c9:b8:00:f4:80:69:1b:d6:b6:09:63:46:6b:0c:75")
}
