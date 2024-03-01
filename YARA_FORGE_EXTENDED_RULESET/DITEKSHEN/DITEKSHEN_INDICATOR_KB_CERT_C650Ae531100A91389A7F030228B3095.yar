import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_C650Ae531100A91389A7F030228B3095 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "80ee9422-190d-5a4e-9a4c-fb8d1b2e2f8c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4062-L4073"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e5afd76711e1b466d7eba742f50c7f9551498796f0aca45566bd9686034efac3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "05eebfec568abc5fc4b2fd9e5eca087b02e49f53"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "POKEROWA STRUNA SP Z O O" and pe.signatures[i].serial=="c6:50:ae:53:11:00:a9:13:89:a7:f0:30:22:8b:30:95")
}
