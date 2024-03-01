import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_02D17Fbf4869F23Fea43C7863902Df93 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "6e96f5b2-f3de-5d5a-babe-d46b9e3edd3e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1322-L1333"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a66e10934cc58e364a694dde3865d0de33e61ce0128ef144c61fa5728d22b8f8"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d336ff8d8ccb771943a70bb4ba11239fb71beca5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Microsoft Windows" and pe.signatures[i].serial=="02:d1:7f:bf:48:69:f2:3f:ea:43:c7:86:39:02:df:93")
}
