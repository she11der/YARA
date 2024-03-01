import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Taffias : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7ace9b76-104c-511a-801b-0c2d5860eaba"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3150-L3161"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "dc6b65757ceb3818101c8694680d1f44af3726876bef30843cfc2cb51ec6ea02"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "88d563dccb2ffc9c5f6d6a3721ad17203768735a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TAFFIAS" and pe.signatures[i].serial=="00")
}
