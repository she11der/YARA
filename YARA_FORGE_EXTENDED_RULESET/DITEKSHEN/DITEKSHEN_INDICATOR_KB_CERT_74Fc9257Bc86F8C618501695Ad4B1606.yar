import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_74Fc9257Bc86F8C618501695Ad4B1606 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c0ed5369-ca51-50b8-941a-580262b4f644"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8836-L8849"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d6a9956d8bcc717186c205d07b94df1df4818bee58f98bdc128ec569331ab5e6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8ebbb2ab8f2e1366d0137e5026e07fde229f45f39d043c7ad36091b8eb2a923e"
		reason = "ParallaxRAT"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "169Teaco Limited" and pe.signatures[i].serial=="74:fc:92:57:bc:86:f8:c6:18:50:16:95:ad:4b:16:06")
}
