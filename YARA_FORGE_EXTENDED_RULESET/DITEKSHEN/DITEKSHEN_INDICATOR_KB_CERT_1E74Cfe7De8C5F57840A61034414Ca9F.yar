import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1E74Cfe7De8C5F57840A61034414Ca9F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "b46992d5-f4fb-5e51-8f3c-eb87d4397f14"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1335-L1346"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "14f57732a82b5139059bbe6f713184659187b57419d79e85a12ab197def4b761"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2dfa711a12aed0ace72e538c57136fa021412f95951c319dcb331a3e529cf86e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Insta Software Solution Inc." and pe.signatures[i].serial=="1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f")
}
