import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_205B80A74A5Dddedea6B84A1E1C44010 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "43e34fe4-e580-572e-a14e-5ee58b3bf594"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3308-L3319"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1af8527193acdbcb3ba0239879c3b23c6ba4e68d920ae4d5ce503d44e32991f7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1a743595dfaa29cd215ec82a6cd29bb434b709cf"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Befadbffde" and pe.signatures[i].serial=="20:5b:80:a7:4a:5d:dd:ed:ea:6b:84:a1:e1:c4:40:10")
}
