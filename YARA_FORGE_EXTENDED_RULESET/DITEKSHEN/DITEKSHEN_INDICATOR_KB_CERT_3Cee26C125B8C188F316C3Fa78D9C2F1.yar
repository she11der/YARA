import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3Cee26C125B8C188F316C3Fa78D9C2F1 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d9271a74-1a04-5863-afc6-4b1d2982f680"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2848-L2859"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "673a275a6d899b5de66d80cb55fa6438c2e14c70a96ba8461eb4946e1f4b4dfa"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9efcf68a289d9186ec17e334205cb644c2b6a147"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bitubit LLC" and pe.signatures[i].serial=="3c:ee:26:c1:25:b8:c1:88:f3:16:c3:fa:78:d9:c2:f1")
}
