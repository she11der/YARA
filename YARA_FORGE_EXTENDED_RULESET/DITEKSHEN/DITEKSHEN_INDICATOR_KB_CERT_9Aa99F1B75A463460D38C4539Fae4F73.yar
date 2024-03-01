import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_9Aa99F1B75A463460D38C4539Fae4F73 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5ffad411-49e2-5691-95e7-1e294a2a101e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2913-L2924"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b73c6ca2c0cd0e09f0add77c3af3c8e16f46cec29b49d4dcab5a569fed8d3d39"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b2ea9e771631f95a927c29b044284ef4f84a2069"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beaacdfaeeccbbedadcb" and pe.signatures[i].serial=="9a:a9:9f:1b:75:a4:63:46:0d:38:c4:53:9f:ae:4f:73")
}
