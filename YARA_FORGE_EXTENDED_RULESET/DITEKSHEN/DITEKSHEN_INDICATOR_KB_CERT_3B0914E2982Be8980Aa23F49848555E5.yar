import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3B0914E2982Be8980Aa23F49848555E5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "bda3e8b2-5d1b-5898-a4c3-318fc88506b8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8851-L8864"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b1ced5176720e0a3bd475172a167675de8211987fbae11b93eab1fba6b3629f5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "254e59ea93fa5f2a6af44f9631660f7b6cca4b4c9f97046405bcfed5589a32fa"
		reason = "ParallaxRAT"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Office Rat s.r.o." and pe.signatures[i].serial=="3b:09:14:e2:98:2b:e8:98:0a:a2:3f:49:84:85:55:e5")
}
