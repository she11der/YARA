import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_738Db9460A10Bb8Bc03Dc59Feac3Be5E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3451fe9d-067a-57ea-9df1-35d427d8c71a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2573-L2584"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6a7060f2a5867e9974cb01de516ef34fb367ef9acf88e2f63c97dd05b1676504"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4cf77e598b603c13cdcd1a676ca61513558df746"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jocelyn Bennett" and pe.signatures[i].serial=="73:8d:b9:46:0a:10:bb:8b:c0:3d:c5:9f:ea:c3:be:5e")
}
