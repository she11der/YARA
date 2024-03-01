import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_040F11F124A73Bdecc41259845A8A773 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0502773a-356e-5eae-9c37-e1ef89de3547"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5458-L5469"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "70edbe8be481ccb7b5c6a6485c2ac249ec5120a4cde18d551954cfeaae121f27"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6f332f7e78cac4a6c35209fde248ef317f7a23e8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TrustPort" and pe.signatures[i].serial=="04:0f:11:f1:24:a7:3b:de:cc:41:25:98:45:a8:a7:73")
}
