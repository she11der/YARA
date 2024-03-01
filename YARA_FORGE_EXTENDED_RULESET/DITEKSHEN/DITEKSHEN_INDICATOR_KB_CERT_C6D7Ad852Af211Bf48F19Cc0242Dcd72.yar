import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_C6D7Ad852Af211Bf48F19Cc0242Dcd72 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1aca90d4-6cb6-5bcd-a4c9-e8f8cddc0d04"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4296-L4307"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e10de48bfa1edec81157eb95ef3478346c22dd6f7ef163e30887d3c7bb580c5e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "bddcef09f222ea4270d4a1811c10f4fcf98e4125"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APDZQKILIIQVIJSCTY" and pe.signatures[i].serial=="c6:d7:ad:85:2a:f2:11:bf:48:f1:9c:c0:24:2d:cd:72")
}
