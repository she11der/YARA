import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_101D6A5A29D9A77807553Ceac669D853 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8554ce79-fd87-54ac-b538-e2899fe95414"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8641-L8654"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "be6b5a98d5c218c39d8f10bc2a0e443bc8be8a591ab368ee902de4a45a95c8d2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "cd6aa9a7a4898e42b8361dc3542d0afb72e6deefc0b85ebfb55d282a2982b994"
		reason = "IcedID"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BIC GROUP LIMITED" and pe.signatures[i].serial=="10:1d:6a:5a:29:d9:a7:78:07:55:3c:ea:c6:69:d8:53")
}
