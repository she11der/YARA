import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2C90Eaf4De3Afc03Ba924C719435C2A3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0b1ae208-bf81-55d0-b4e5-b1c1f7556387"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1559-L1570"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "792898b34ebe4dfc603b3f3b54777a86827a52fd3699a799e95c436317be77da"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6b916111ffbd6736afa569d7d940ada544daf3b18213a0da3025b20973a577dc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AntiFIX s.r.o." and pe.signatures[i].serial=="2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3")
}
