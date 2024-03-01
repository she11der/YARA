import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5226A724Cfa0B4Bc0164Ecda3F02A3Dc : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "37d1061f-80b1-5944-bde3-6279633e321a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8596-L8609"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "8fa1dad2cd4c1406c1346bbe0fef88eba415437d159cf9010dcfaaa7210aef0e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "92f005b9c46c7993205d9451823cf0410d1afbd7056a7dcdfa2b8b3da74ee1bf"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VALENTE SP Z O O" and pe.signatures[i].serial=="52:26:a7:24:cf:a0:b4:bc:01:64:ec:da:3f:02:a3:dc")
}
