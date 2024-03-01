import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_40E27B7404Aa9B485F8A2Fc0C8E53Af3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1aee45e6-ff0b-56a6-a50e-284bf2122e3b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7657-L7668"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "95a0bcf9b52ba8f4b63453abf0ee28027689450557a2408c6b27f8aafcbbe945"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ca468ff8403a8416042705e79dbc499a5ea9be85"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Southern Wall Systems, LLC" and pe.signatures[i].serial=="40:e2:7b:74:04:aa:9b:48:5f:8a:2f:c0:c8:e5:3a:f3")
}
