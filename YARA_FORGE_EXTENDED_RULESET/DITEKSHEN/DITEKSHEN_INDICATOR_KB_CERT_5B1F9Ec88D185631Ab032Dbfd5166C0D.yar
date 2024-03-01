import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5B1F9Ec88D185631Ab032Dbfd5166C0D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "233466e6-7b5f-50d7-967a-976b698e9194"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8281-L8294"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "05428b4e636a60fb409ead0f4aeb25ed08dae24d58c98a17bb77aa521706763a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a46234c01e9f9904e500aefad4b5718d86aaec4e084b3d8ffbfe5724f8ddda45"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TOPFLIGHT GROUP LIMITED" and pe.signatures[i].serial=="5b:1f:9e:c8:8d:18:56:31:ab:03:2d:bf:d5:16:6c:0d")
}
