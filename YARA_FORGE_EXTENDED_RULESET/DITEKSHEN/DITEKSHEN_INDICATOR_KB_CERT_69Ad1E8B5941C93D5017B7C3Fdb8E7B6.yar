import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_69Ad1E8B5941C93D5017B7C3Fdb8E7B6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4b961b30-dc0d-513c-8a66-ed8fe71f5439"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7127-L7138"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "1a37133dcc7af9c3f229f517dca847d7c007b8a2fdc6af50721d68f68c5d9c20"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9b6f3b3cd33ae938fbc5c95b8c9239bac9f9f7bf"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Afia Wave Enterprises Oy" and pe.signatures[i].serial=="69:ad:1e:8b:59:41:c9:3d:50:17:b7:c3:fd:b8:e7:b6")
}
