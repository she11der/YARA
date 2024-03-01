import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1Fb984D5A7296Ba74445C23Ead7D20Aa : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1e290f81-11ab-5d5f-ab7a-c703c875bde4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3607-L3618"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ff29013eb20bccbec16107404fc18b07c87ac5269b788c48a49a490271e94052"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c852fc9670391ff077eb2590639051efa42db5c9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DrWeb Digital LLC" and pe.signatures[i].serial=="1f:b9:84:d5:a7:29:6b:a7:44:45:c2:3e:ad:7d:20:aa")
}
