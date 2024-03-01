import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_030Ba877Daf788A0048D04A85B1F6Eca : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "66689847-aa67-5029-9f37-cc410a564633"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7224-L7235"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "70b5b9011b53b7c9ac9dc286f3512a7a8bec5ec35ade0ee1c4bedd0a128994da"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1f10c5676a742548fb430fbc1965b20146b7325a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Skylum Software USA, Inc." and pe.signatures[i].serial=="03:0b:a8:77:da:f7:88:a0:04:8d:04:a8:5b:1f:6e:ca")
}
