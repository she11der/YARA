import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_E573D9C8B403C41Bd59Ffa0A8Efd4168 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "683ea9a6-2002-5c48-8512-51f65e70dd2c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8206-L8219"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ec53ab007d8be2f3cad45e787e724c5af0dd3f18c2b66a179b822bdeeb0d1560"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a9ab2be0ea677c6c6ed67b23cfee0fa44bfb346a4bb720f10a3f02a78b8f5c82"
		reason = "Dridex"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VERONIKA 2\" OOO\"" and pe.signatures[i].serial=="e5:73:d9:c8:b4:03:c4:1b:d5:9f:fa:0a:8e:fd:41:68")
}
