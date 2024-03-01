import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0F2B44E398Ba76C5F57779C41548607B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "6a962fd8-c2cd-5abd-8f80-95697771037c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1019-L1030"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "172622595a3f6a6ab4ac2677c3064fab87b0a872c261031331c99cbd58671da2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "cef53e9ca954d1383a8ece037925aa4de9268f3f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DIGITAL DR" and pe.signatures[i].serial=="0f:2b:44:e3:98:ba:76:c5:f5:77:79:c4:15:48:60:7b")
}
