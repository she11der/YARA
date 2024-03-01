import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_332Bd5801E8415585E72C87E0E2Ec71D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a4e1560f-12e4-5f49-a714-7df939dad513"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8056-L8069"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ad3b1aebedd1ecef9af96da991cdbaca8033e0d48b5e7b776dd3fd3c4024928e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "47338c1a0ea425c47dede188d10ca95288514f369fe8a5105752bd8d906b8cbc"
		reason = "NetSupport"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Elite Marketing Strategies, Inc." and pe.signatures[i].serial=="33:2b:d5:80:1e:84:15:58:5e:72:c8:7e:0e:2e:c7:1d")
}
