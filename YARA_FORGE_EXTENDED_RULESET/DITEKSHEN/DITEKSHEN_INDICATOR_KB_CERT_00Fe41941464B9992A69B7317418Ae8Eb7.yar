import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Fe41941464B9992A69B7317418Ae8Eb7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "44626304-7f68-5d3a-81b4-91ee0bd09cc3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2066-L2077"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "713a2cfc95b83de71064e198b26b716790c7cf21674961720695ab6749cb2ad1"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ef4da71810fb92e942446ee1d9b5f38fea49628e0d8335a485f328fcef7f1a20"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Milsean Software Limited" and pe.signatures[i].serial=="00:fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7")
}
