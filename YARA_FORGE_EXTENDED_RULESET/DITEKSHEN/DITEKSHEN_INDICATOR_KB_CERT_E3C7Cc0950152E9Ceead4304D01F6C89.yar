import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_E3C7Cc0950152E9Ceead4304D01F6C89 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "8bea34fa-3620-5f5f-895f-3baa3b7b458a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1478-L1489"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "395ed4c9c8668f6416632f85883c5fd5b6038ce8388410f22bcbe2a9e6281c35"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "82975e3e21e8fd37bb723de6fdb6e18df9d0e55f0067cc77dd571a52025c6724"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DNS KOMPLEKT" and pe.signatures[i].serial=="e3:c7:cc:09:50:15:2e:9c:ee:ad:43:04:d0:1f:6c:89")
}
