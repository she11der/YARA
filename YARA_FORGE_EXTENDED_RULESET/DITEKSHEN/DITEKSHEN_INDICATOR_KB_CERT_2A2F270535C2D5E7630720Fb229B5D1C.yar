import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2A2F270535C2D5E7630720Fb229B5D1C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3ed98546-92b2-5566-9716-ae8209ece9d6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7831-L7844"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7d9785c12d2d744fbafab009edfb1ef232eadcdbc8eee99d0ad0daacabbabf26"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "73a0cc4495a49492806b970fd844a0ab078126930305d22c7bf68b43c337fc1a"
		reason = "IcedID"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KOZUZ SP. Z O.O." and pe.signatures[i].serial=="2a:2f:27:05:35:c2:d5:e7:63:07:20:fb:22:9b:5d:1c")
}
