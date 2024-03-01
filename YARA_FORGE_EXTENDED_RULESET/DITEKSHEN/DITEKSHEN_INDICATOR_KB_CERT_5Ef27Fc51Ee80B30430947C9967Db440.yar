import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5Ef27Fc51Ee80B30430947C9967Db440 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "53f7b334-8feb-5581-a64c-5db6558a6434"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8926-L8939"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e282054102d852c0f66435148ce97050b15fb6f60f5d1bfc875b02de9c50c297"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c2dcc4a1ea16e45f86828e81eda20f83e70cbf77e152ddd80b1b4a730ef77551"
		reason = "RedLineStealer"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and pe.signatures[i].serial=="5e:f2:7f:c5:1e:e8:0b:30:43:09:47:c9:96:7d:b4:40")
}
