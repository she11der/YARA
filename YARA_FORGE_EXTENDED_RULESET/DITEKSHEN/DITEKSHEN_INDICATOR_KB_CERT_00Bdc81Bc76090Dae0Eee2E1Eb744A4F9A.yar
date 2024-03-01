import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Bdc81Bc76090Dae0Eee2E1Eb744A4F9A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9c91e39e-a120-537d-a24c-f0b8ffe9dd6e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1572-L1583"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "90c695b0cffd4786471faca21b77161ae6e930540766c4f18796a7adea74b6f5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a3b0a1cd3998688f294838758688f96adee7d5aa98ec43709b8868d6914e96c1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALM4U GmbH" and pe.signatures[i].serial=="00:bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a")
}
