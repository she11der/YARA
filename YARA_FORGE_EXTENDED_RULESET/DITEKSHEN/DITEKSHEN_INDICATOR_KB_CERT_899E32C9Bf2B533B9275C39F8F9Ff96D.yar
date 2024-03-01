import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_899E32C9Bf2B533B9275C39F8F9Ff96D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "62ecae58-7576-5170-8eb5-2becd292e5de"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3373-L3384"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c5fe3726fd19d050e762cc9e4e2099e74e3780c89a75dab55c12e16bfecd8642"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "329af76d7c84a90f2117893adc255115c3c961c7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eecaaffcbfdffaedcfec" and pe.signatures[i].serial=="89:9e:32:c9:bf:2b:53:3b:92:75:c3:9f:8f:9f:f9:6d")
}
