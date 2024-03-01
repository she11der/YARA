import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B1Aea98Bf0Ce789B6C952310F14Edde0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9ab5382f-d768-553c-b52c-88d3a3824459"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2521-L2532"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f7e8a4a0dcd952129e24e8e9351f271d7ea98ffcb7ef9ebe65c27dcc62e6a820"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "28324a9746edbdb41c9579032d6eb6ab4fd3e0906f250d4858ce9c5fe5e97469"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Absolut LLC" and pe.signatures[i].serial=="00:b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0")
}
