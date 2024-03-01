import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0086909B91F07F9316984D888D1E28Ab76 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "58b191cc-82f2-5ad3-8d1e-91c7528880c6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4405-L4416"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "eb8807437edbbba52a928de4ebf0a25513127bd9800088e0d85e41c8375a05b1"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5eba3c38e989c7d16c987e2989688d3bd24032bc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dantherm Intelligent Monitoring A/S" and pe.signatures[i].serial=="00:86:90:9b:91:f0:7f:93:16:98:4d:88:8d:1e:28:ab:76")
}
