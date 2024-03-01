import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_029685Cda1C8233D2409A31206F78F9F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2c1d858b-3adc-5c05-bc72-2a6f12f7245e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4955-L4966"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a7eec901d92d6126cbc4468d7f2fbccc905f550c7dc8d28b405f583cfde9aea3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "86574b0ef7fbce15f208bf801866f34c664cf7ce"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KOTO TRADE" and pe.signatures[i].serial=="02:96:85:cd:a1:c8:23:3d:24:09:a3:12:06:f7:8f:9f")
}
