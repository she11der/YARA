import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7B91468122273Aa32B7Cfc80C331Ea13 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "4369d88d-f592-5a5a-bdf6-c63b77d45326"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1361-L1372"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "4c0fa18edb23c6a7474185adc67101ad9b13c71188f25612165cb97d236562d8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "409f32dc91542546e7c7f85f687fe3f1acffdd853657c8aa8c1c985027f5271d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO KBI" and pe.signatures[i].serial=="7b:91:46:81:22:27:3a:a3:2b:7c:fc:80:c3:31:ea:13")
}
