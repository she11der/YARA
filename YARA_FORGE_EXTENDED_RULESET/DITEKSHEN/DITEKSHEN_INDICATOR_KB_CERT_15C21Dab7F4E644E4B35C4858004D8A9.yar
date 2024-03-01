import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_15C21Dab7F4E644E4B35C4858004D8A9 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7dac5657-038f-5cbd-a854-cdb12921121e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8626-L8639"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "646a858b10de89da4e639d3902ada78fad3a45868f0d7782546a865396cf226c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "34a9cd401a5a86c5194954df3a497094c01b6603264aab5cf7d9b3c4a0074801"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "P.REGO, s.r.o." and pe.signatures[i].serial=="15:c2:1d:ab:7f:4e:64:4e:4b:35:c4:85:80:04:d8:a9")
}
