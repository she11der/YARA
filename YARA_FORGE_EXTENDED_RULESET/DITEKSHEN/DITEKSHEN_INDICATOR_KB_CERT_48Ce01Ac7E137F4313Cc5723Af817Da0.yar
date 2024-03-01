import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_48Ce01Ac7E137F4313Cc5723Af817Da0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "d5eb08a7-eb2b-5318-a941-da3ce0a6b634"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1045-L1056"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d92d4aa491b028620f17fd997a782f5e75247b2d3de7ef9026e2c62309275ce1"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8f594f2e0665ffd656160aac235d8c490059a9cc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ET HOMES LTD" and pe.signatures[i].serial=="48:ce:01:ac:7e:13:7f:43:13:cc:57:23:af:81:7d:a0")
}
