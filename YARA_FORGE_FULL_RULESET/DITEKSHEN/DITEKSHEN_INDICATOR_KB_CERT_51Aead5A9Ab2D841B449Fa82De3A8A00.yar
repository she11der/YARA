import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_51Aead5A9Ab2D841B449Fa82De3A8A00 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d64ff10d-e4dd-5d89-a600-d136571be940"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1936-L1947"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1658a12bb040b5b16c61469fe52abbaaecf5bd66bf5e45a2c2da9f80fa0c66f5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "155edd03d034d6958af61bc6a7181ef8f840feae68a236be3ff73ce7553651b0"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Corsair Software Solution Inc." and pe.signatures[i].serial=="51:ae:ad:5a:9a:b2:d8:41:b4:49:fa:82:de:3a:8a:00")
}
