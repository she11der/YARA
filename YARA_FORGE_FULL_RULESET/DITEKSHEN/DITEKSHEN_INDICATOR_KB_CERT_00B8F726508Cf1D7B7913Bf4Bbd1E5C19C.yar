import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B8F726508Cf1D7B7913Bf4Bbd1E5C19C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0acaaed9-ba18-56b0-95b9-e05181843129"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6684-L6698"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "71eb50a47465d69dbdd488c57b3fd9f70a4dd3b0bc086ed14038320928bc947e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0711adcedb225b82dc32c1435ff32d0a1e54911a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TMerkuri LLC" and (pe.signatures[i].serial=="b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c" or pe.signatures[i].serial=="00:b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c"))
}
