import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_41D05676E0D31908Be4Dead3486Aeae3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d668f53b-3d1c-5fcb-9f9c-2923e63f93a9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1806-L1817"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e4eb406e433b38ac127ba22040c48b510636eb55e2b524b02386710709d343b6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e6e597527853ee64b45d48897e3ca4331f6cc08a88cc57ff2045923e65461598"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rov SP Z O O" and pe.signatures[i].serial=="41:d0:56:76:e0:d3:19:08:be:4d:ea:d3:48:6a:ea:e3")
}
