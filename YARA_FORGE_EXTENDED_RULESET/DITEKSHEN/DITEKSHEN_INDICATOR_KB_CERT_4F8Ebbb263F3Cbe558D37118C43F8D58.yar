import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4F8Ebbb263F3Cbe558D37118C43F8D58 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c273f7e4-8c88-5205-be4b-3a8e8bed144e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4075-L4086"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e502e7e08fa82f8bd1b2b15c34999ece6b3d59d75ab1a4dda05b4b9440c49b7c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3f27a35fe7af06977138d02ad83ddbf13a67b7c3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Maxthon Technology Co, Ltd." and pe.signatures[i].serial=="4f:8e:bb:b2:63:f3:cb:e5:58:d3:71:18:c4:3f:8d:58")
}
