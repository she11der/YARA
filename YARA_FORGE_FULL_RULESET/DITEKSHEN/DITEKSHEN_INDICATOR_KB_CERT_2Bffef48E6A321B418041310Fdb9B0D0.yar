import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2Bffef48E6A321B418041310Fdb9B0D0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "fc945c76-b743-52d3-8e15-77afdc629f6d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L785-L796"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8d0223b6366f7bc22fd6dd053c1fb6c9e52f80b3bdf9ee46017ddf038bd1e00f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c40c5157e96369ceb7e26e756f2d1372128cee7b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "A&D DOMUS LIMITED" and pe.signatures[i].serial=="2b:ff:ef:48:e6:a3:21:b4:18:04:13:10:fd:b9:b0:d0")
}
