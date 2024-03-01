import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3C5Fc5D02273F297404F7B9306E447Bb : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2dd0805d-f43e-5aec-a0d9-98fc9fa6c088"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5734-L5745"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e73fd0a38c76783e3110abe82411cc3d22fbbc95684667dc754618f590f29970"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3fa4a6efd5e443627e9e32e6effe04c991f4fe8f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Wirpool Soft" and pe.signatures[i].serial=="3c:5f:c5:d0:22:73:f2:97:40:4f:7b:93:06:e4:47:bb")
}
