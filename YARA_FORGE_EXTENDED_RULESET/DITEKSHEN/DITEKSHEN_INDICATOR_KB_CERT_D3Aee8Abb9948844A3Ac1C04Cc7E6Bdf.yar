import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_D3Aee8Abb9948844A3Ac1C04Cc7E6Bdf : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8b17b23f-3296-55b2-8e7b-40e13a14a610"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8791-L8804"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9af0b27e96575298a31b53f6f88cdb20934db75637abdd0acb40bb3c6921542c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e386450257e170981513b7001a82fb029f0931e5c2f11c6d9b86660da0b89a66"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HOUSE 9A s.r.o" and pe.signatures[i].serial=="d3:ae:e8:ab:b9:94:88:44:a3:ac:1c:04:cc:7e:6b:df")
}
