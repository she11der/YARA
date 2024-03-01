import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_61B11Ef9726Ab2E78132E01Bd791B336 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5b830ab1-16d2-573c-81b7-b8b922af6f4b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5988-L5999"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "50c89d732409ff680734f481d858256001245c10345d9e6f1cbb51dcdc9c2cc9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9f7fcfd7e70dd7cd723ac20e5e7cb7aad1ba976b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Skalari" and pe.signatures[i].serial=="61:b1:1e:f9:72:6a:b2:e7:81:32:e0:1b:d7:91:b3:36")
}
