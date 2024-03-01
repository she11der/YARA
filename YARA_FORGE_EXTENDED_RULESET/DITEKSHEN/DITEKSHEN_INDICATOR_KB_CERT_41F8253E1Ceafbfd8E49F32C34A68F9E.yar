import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_41F8253E1Ceafbfd8E49F32C34A68F9E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "84bd03de-88cd-5180-af11-916dbecd0366"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4140-L4151"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "53f71030815dcdda8424fe858d26a08cf947a683e69c50ea5fda53f51b88bb93"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "02e739740b88328ac9c4a6de0ee703b7610f977b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shenzhen Smartspace Software technology Co.,Limited" and pe.signatures[i].serial=="41:f8:25:3e:1c:ea:fb:fd:8e:49:f3:2c:34:a6:8f:9e")
}
