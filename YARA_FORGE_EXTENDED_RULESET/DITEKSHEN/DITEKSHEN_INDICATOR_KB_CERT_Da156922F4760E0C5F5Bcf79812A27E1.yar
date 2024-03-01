import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Da156922F4760E0C5F5Bcf79812A27E1 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "065bacbc-3004-53c1-ba73-4779743e8221"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8581-L8594"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f6dd0f2373e412a753cbe5e27152f48d6c8980de9b26e5ab212b926e7e41c813"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6e19e012f55e0bb44e9036d4445ab945942965dcb81b9ed24ad6fc17933c4fce"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DRINK AND BUBBLE LTD" and pe.signatures[i].serial=="da:15:69:22:f4:76:0e:0c:5f:5b:cf:79:81:2a:27:e1")
}
