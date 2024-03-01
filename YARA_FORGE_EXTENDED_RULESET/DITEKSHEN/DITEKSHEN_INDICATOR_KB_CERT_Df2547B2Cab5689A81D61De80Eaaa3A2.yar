import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Df2547B2Cab5689A81D61De80Eaaa3A2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4eba17f8-df3c-552d-90b5-faef7b860203"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8251-L8264"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c32a6510bd3cfd09e84ccf36140eb405945059c981fb1888298501493f6ef68f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4c6e21a6e96ea6fae6c142c2d1c919f590d9bf4e5c6b0f3ec7f9b0a38f3ce45d"
		reason = "IcedID"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORWARD MUSIC AGENCY SRL" and pe.signatures[i].serial=="df:25:47:b2:ca:b5:68:9a:81:d6:1d:e8:0e:aa:a3:a2")
}
