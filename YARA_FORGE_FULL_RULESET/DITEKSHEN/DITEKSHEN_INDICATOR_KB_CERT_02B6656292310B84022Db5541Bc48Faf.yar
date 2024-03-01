import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_02B6656292310B84022Db5541Bc48Faf : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "252c8339-73d3-5de0-8f75-78a6a2da4abc"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5086-L5097"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "374f7abfab6f7def8b895dc9536ca6bb7a605e9478934af6c97e8b7595fbee19"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "bb58a3d322fd67122804b2924ad1ddc27016e11a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DILA d.o.o." and pe.signatures[i].serial=="02:b6:65:62:92:31:0b:84:02:2d:b5:54:1b:c4:8f:af")
}
