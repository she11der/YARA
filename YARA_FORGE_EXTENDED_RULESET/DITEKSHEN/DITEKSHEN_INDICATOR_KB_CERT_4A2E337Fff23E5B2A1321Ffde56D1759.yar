import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4A2E337Fff23E5B2A1321Ffde56D1759 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "60d218b2-5297-59e6-9370-fc0ba036c688"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8116-L8129"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "524048d39de89002efbb8bf75135551b300e03f1126e5e117a4682c79ec04c9a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "67099e0c41c102535d388fab1de576433f2ded2b08fb7da1bf66e3bdaba4eeb4"
		reason = "IcedID"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Karolina Klimowska" and pe.signatures[i].serial=="4a:2e:33:7f:ff:23:e5:b2:a1:32:1f:fd:e5:6d:17:59")
}
