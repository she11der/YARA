import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D3356318924C8C42959Bf1D1574E6482 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7e23e9cf-5a34-55bb-a88d-4c0aef411372"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4888-L4899"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "86ca8da7e9e704f64be8ecd9e270108337d28b540ba8cd669a8d536ccfefea95"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e21f261f5cf7c2856bd9da5a5ed2c4e2b2ef4c9a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ADV TOURS d.o.o." and pe.signatures[i].serial=="00:d3:35:63:18:92:4c:8c:42:95:9b:f1:d1:57:4e:64:82")
}
