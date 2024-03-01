import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_670C3494206B9F0C18714Fdcffaaa42F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "cbe10923-794e-50f0-bcc7-026ca2235836"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7043-L7054"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "5215f3e877ac4b37d33a29f9d2e92567db02f41f5fa1592d2de199ee06b43885"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "59612473a9e23dc770f3a33b1ef83c02e3cfd4b6"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ADRIATIK PORT SERVIS, d.o.o." and pe.signatures[i].serial=="67:0c:34:94:20:6b:9f:0c:18:71:4f:dc:ff:aa:a4:2f")
}
