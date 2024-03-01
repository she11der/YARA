import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4D26Bab89Fcf7Ff9Fa4Dc4847E563563 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "168281bf-35ad-542a-adb4-20d719e31e2d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3984-L3995"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "3eadf6eda2819101a370688d636250085915be3ebf1b3dec7a86d12a6a5ce681"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2be34a7a39df38f66d5550dcfa01850c8f165c81"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "qvarn pty ltd" and pe.signatures[i].serial=="4d:26:ba:b8:9f:cf:7f:f9:fa:4d:c4:84:7e:56:35:63")
}
