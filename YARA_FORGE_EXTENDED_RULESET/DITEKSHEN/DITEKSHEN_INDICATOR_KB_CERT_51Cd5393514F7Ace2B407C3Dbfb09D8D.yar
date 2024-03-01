import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_51Cd5393514F7Ace2B407C3Dbfb09D8D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "f2f7b08e-111c-570b-b376-79145050ca42"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L146-L157"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "389dbdc85035fdd94e831940eda910349134600e921720729840c932123db36d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "07a9fd6af84983dbf083c15983097ac9ce761864"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APPI CZ a.s" and pe.signatures[i].serial=="51:cd:53:93:51:4f:7a:ce:2b:40:7c:3d:bf:b0:9d:8d")
}
