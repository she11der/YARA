import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0F0Ed5318848703405D40F7C62D0F39A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "6baebaa7-275c-571d-b321-9a21d7799a33"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5962-L5973"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "77bd8fd2dc48e2fc8abbf0f3411dfa8010326b6a9928fb392cce6e0fe8e9d309"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ed91194ee135b24d5df160965d8036587d6c8c35"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SIES UPRAVLENIE PROTSESSAMI, OOO" and pe.signatures[i].serial=="0f:0e:d5:31:88:48:70:34:05:d4:0f:7c:62:d0:f3:9a")
}
