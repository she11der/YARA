import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2D8Cfcf04209Dc7F771D8D18E462C35A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "6b2b25af-dae5-5055-851d-e515f6beee58"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7386-L7398"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e7eee6a6593c231c193145eeefd03a0f32c1d8cc103c97cfa26b5af7363c9b08"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a9c61e299634ba01e269239de322fb85e2da006b"
		hash1 = "af27173ed576215bb06dab3a1526992ee1f8bd358a92d63ad0cfbc0325c70acf"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AA PLUS INVEST d.o.o." and pe.signatures[i].serial=="2d:8c:fc:f0:42:09:dc:7f:77:1d:8d:18:e4:62:c3:5a")
}
