import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_05D50A0E09Bb9A836Ffb90A3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f6947bf1-7f20-5be5-a242-c1025be40055"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8521-L8534"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "fc38ae0c9d4fc26739deab65ae3669f272e999b76dbc521dae04b9a3e3e7cef0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2d072e0e80885a82d5e35806b052ca416994e0fe06da1cfdcebd509d967a1aae"
		reason = "ParallaxRAT"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Toliz Info Tech Solutions INC." and pe.signatures[i].serial=="05:d5:0a:0e:09:bb:9a:83:6f:fb:90:a3")
}
