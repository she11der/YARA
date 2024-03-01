import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6Daa67498C3A5D8133F28Fefe9Ccc20E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5eb899b3-347d-5e74-8afa-29ffa73c7231"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7741-L7754"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "dc66a18e4f8d14f98e5a8073d32b641e0eb795e989fb62ac23207e765838561a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f54146fadad277f67b14cfebd13cbada9789281cee7165db0277ad51621adb97"
		reason = "ParallaxRAT"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rimsara Development OU" and pe.signatures[i].serial=="6d:aa:67:49:8c:3a:5d:81:33:f2:8f:ef:e9:cc:c2:0e")
}
