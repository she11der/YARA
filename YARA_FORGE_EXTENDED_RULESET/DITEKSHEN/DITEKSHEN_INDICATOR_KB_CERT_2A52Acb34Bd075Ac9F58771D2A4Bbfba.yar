import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2A52Acb34Bd075Ac9F58771D2A4Bbfba : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2d6b6ff5-e081-5e91-b03f-6e0d02afdb8f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2235-L2246"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9ffad34a94e9210bb98021c0ee0ddba4144406cca976537efe24e63367a295cd"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c839065a159bec7e63bfdcb1794889829853c07f7a931666f4eb84103302c1c9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Katarzyna Galganek mim e coc" and pe.signatures[i].serial=="2a:52:ac:b3:4b:d0:75:ac:9f:58:77:1d:2a:4b:bf:ba")
}
