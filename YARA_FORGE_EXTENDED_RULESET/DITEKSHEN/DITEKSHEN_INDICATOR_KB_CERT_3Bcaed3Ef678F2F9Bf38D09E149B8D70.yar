import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3Bcaed3Ef678F2F9Bf38D09E149B8D70 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "decdae98-333f-58b3-8c48-b997da5fc3f3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2118-L2129"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9981e0aed672ebfcbe7f0bc1eee6a26a1523b8577d5ee572612aaebf23d1fbcf"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "45d598691e79be3c47e1883d4b0e149c13a76932ea630be429b0cfccf3217bc2"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "StarY Media Inc." and pe.signatures[i].serial=="3b:ca:ed:3e:f6:78:f2:f9:bf:38:d0:9e:14:9b:8d:70")
}
