import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4679C5398A279318365Fd77A84445699 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ff4061e7-5e45-596f-9d40-c33661a18e71"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8656-L8669"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "1c591cbb2d35d8dad01ff4ea8c71c8b3a0a5f999f1edfcfc038e47f96d3a3a67"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8fcef52c16987307f4e1f7d4b62304c65aedb952c90bb2ead8321f1e1d7c9a6e"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HURT GROUP HOLDINGS LIMITED" and pe.signatures[i].serial=="46:79:c5:39:8a:27:93:18:36:5f:d7:7a:84:44:56:99")
}
