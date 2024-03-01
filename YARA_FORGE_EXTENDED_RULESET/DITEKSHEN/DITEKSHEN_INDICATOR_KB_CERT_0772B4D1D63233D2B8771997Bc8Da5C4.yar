import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0772B4D1D63233D2B8771997Bc8Da5C4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a05a2bc4-a4a3-5e86-9a1c-ed82de7786df"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8356-L8369"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "056fefbc03cff00a40ea9bb65893b92fcc15134c7cf7bf7dedf98f43b44bc03d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c6a78692f2fda8908933fb3f1df68592eb5da129caafd33329d1b804006973f7"
		reason = "IcedID"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Maya logistika d.o.o." and pe.signatures[i].serial=="07:72:b4:d1:d6:32:33:d2:b8:77:19:97:bc:8d:a5:c4")
}
