import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1Ffc9825644Caf5B1F521780C5C7F42C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b9ed2db5-b7d4-5d74-bb11-1e8b1dfe1648"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6499-L6510"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9866608a02a043e6873c6fbd231cd733b3b5a1e5b77e3205e5cf53f5ae2bcadd"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4e7e022c7bb6bd90a75674a67f82e839d54a0a5e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ACTIVUS LIMITED" and pe.signatures[i].serial=="1f:fc:98:25:64:4c:af:5b:1f:52:17:80:c5:c7:f4:2c")
}
