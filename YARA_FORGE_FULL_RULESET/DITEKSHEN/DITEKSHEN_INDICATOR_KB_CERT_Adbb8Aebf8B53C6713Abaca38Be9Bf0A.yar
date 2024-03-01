import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Adbb8Aebf8B53C6713Abaca38Be9Bf0A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b3edea3e-8844-58a5-a600-b0695869b2c3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6483-L6497"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "d5e85240df57bf3b5ec4f690943f71609aaf2fb2f751b2919b6024b4247cd571"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9f9b9f5a85d3005e4c613b6c2ba20b6d5d388645"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Konstant LLC" and (pe.signatures[i].serial=="ad:bb:8a:eb:f8:b5:3c:67:13:ab:ac:a3:8b:e9:bf:0a" or pe.signatures[i].serial=="00:ad:bb:8a:eb:f8:b5:3c:67:13:ab:ac:a3:8b:e9:bf:0a"))
}
