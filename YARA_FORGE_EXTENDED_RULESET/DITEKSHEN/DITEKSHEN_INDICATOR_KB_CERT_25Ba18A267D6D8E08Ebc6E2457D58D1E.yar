import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_25Ba18A267D6D8E08Ebc6E2457D58D1E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d2c4907e-cec2-5386-96d3-8c122c7557fa"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8446-L8459"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "38bdfa2291c7c3f81b29d41c65814002db3e4de11928699d2d946e87d313558d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e59824f73703461c2c170681872a28a9bc4731d4b49079aa3afba1d29f83d736"
		reason = "BadNews"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "5Y TECHNOLOGY LIMITED" and pe.signatures[i].serial=="25:ba:18:a2:67:d6:d8:e0:8e:bc:6e:24:57:d5:8d:1e")
}
