import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_28B691272719B1Ee : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5a8cf540-701f-5f94-b630-ccbaa62abfdd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6580-L6591"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b2224f8107e7c50334c7e12963e4e37c0a6824c49842afb314c12d6de9d6bc5e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5dcbc94a2fdcc151afa8c55f24d0d5124d3b6134"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "2021945 Ontario Inc." and pe.signatures[i].serial=="28:b6:91:27:27:19:b1:ee")
}
