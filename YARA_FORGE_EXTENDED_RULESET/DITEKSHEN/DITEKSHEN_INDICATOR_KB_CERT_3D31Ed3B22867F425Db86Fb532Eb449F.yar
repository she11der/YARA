import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3D31Ed3B22867F425Db86Fb532Eb449F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a9924b9e-381a-58b2-8839-fcafeb730a32"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3082-L3093"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e3ec4fcd47867b688241dee693bcec98e633e179757ec8e7afd755c7d53a0cd7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1e708efa130d1e361afb76cc94ba22aca3553590"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Badfcbdbcdbfafcaeebad" and pe.signatures[i].serial=="3d:31:ed:3b:22:86:7f:42:5d:b8:6f:b5:32:eb:44:9f")
}
