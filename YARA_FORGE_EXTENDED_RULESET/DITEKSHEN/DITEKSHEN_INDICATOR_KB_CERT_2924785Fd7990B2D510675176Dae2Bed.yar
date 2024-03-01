import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2924785Fd7990B2D510675176Dae2Bed : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2aedb37c-8991-5750-b0c6-b9d6e7bb5e79"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1702-L1713"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "dbdd714575d3c5f9554026fea97c6e91073d30cf728396111a5106303bb7b624"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "adbc44fda783b5fa817f66147d911fb81a0e2032a1c1527d1b3adbe55f9d682d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Neoopt LLC" and pe.signatures[i].serial=="29:24:78:5f:d7:99:0b:2d:51:06:75:17:6d:ae:2b:ed")
}
