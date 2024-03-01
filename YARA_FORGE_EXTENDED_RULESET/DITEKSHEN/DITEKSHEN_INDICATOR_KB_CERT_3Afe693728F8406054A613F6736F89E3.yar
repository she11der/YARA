import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3Afe693728F8406054A613F6736F89E3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "64c4157e-2183-5f41-b938-df29e210ee80"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7431-L7443"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6993a13546a1eff8a4f770f224a14bffe7e3393f628337cff27cbf57ebab2a65"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "89528e9005a635bcee8da5539e71c5fc4f839f50"
		hash1 = "d98bdf3508763fe0df177ef696f5bf8de7ff7c7dc68bb04a14a95ec28528c3f9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ROB ALDERMAN FITNESS LIMITED" and pe.signatures[i].serial=="3a:fe:69:37:28:f8:40:60:54:a6:13:f6:73:6f:89:e3")
}
