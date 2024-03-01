import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0095E5793F2Abe0B4Ec9Be54Fd24F76Ae5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "94878b56-5b29-55a8-a8ec-7ace588e34ef"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L94-L105"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b1f8867b47c1bec43b3603af343d6d5728ec218a66863a6777c0ee59ae1faa98"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6acdfee2a1ab425b7927d0ffe6afc38c794f1240"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kommservice LLC" and pe.signatures[i].serial=="00:95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5")
}
