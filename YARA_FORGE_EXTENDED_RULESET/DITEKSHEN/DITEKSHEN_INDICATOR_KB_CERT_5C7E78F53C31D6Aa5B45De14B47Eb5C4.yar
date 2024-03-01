import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5C7E78F53C31D6Aa5B45De14B47Eb5C4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e6bd4476-d287-54d9-82b3-d80f328d7831"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1520-L1531"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "0c804e7f1e43a98b150a97adcbba882f7764000abdf7c7408e3361aefa9298b5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f91d436c1c7084b83007f032ef48fecda382ff8b81320212adb81e462976ad5a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cubic Information Systems, UAB" and pe.signatures[i].serial=="5c:7e:78:f5:3c:31:d6:aa:5b:45:de:14:b4:7e:b5:c4")
}
