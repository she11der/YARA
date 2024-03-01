import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_25Ad5Ae68C38Ad1021086F4Ffc8Ba470 : FILE
{
	meta:
		description = "Enigma Protector CA Certificate"
		author = "ditekSHen"
		id = "6f1c6d3a-72a1-5c70-9c7d-1616b13767cd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6379-L6390"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "80b67b804e47fba825fabfee39f9a0aae78a4465b088c28b6f6972acd614bb89"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a04c0281bc2203a95ef9bd6d9736486449d80905"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Enigma Protector CA" and pe.signatures[i].serial=="25:ad:5a:e6:8c:38:ad:10:21:08:6f:4f:fc:8b:a4:70")
}
