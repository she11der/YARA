import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2304Ecf0Ea2B2736Beddd26A903Ba952 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3e064799-2333-5d10-8841-8d0a44ad9c1b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2757-L2768"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c10695440ec4e39cf5b51c926ceeacc13caf3a58006c64b0168a04b4755978a6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d59a63e230cef77951cb73a8d65576f00c049f44"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\x88\\x90\\xE9\\x83\\xBD\\xE5\\x90\\x89\\xE8\\x83\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE8\\xB4\\xA3\\xE4\\xBB\\xBB\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="23:04:ec:f0:ea:2b:27:36:be:dd:d2:6a:90:3b:a9:52")
}
