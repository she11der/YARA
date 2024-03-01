import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2E8023A5A0328F66656E1Fc251C82680 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "192695ab-2f38-5a0b-98ba-5c800f6b9ec1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2547-L2558"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "5f0ff46d6cb2a6fe50a4e433dfbf8f62acd92b7c92d922680894fdaee2558d31"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e3eff064ad23cc4c98cdbcd78e4e5a69527cf2e4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Philippe Mantes" and pe.signatures[i].serial=="2e:80:23:a5:a0:32:8f:66:65:6e:1f:c2:51:c8:26:80")
}
