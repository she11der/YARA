import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1966Bc76Bda1A708334792Da9A336F69 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "254ccdb7-df1c-560a-af68-123ea66c3463"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7683-L7694"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d0293e76f8a595d769fd302829bd94a576d647bbacb586728e804bf4dce1af78"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "29fec27c36efc6809c7269f76cf86ee18cc6ed87"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SYNTHETIC LABS LIMITED" and pe.signatures[i].serial=="19:66:bc:76:bd:a1:a7:08:33:47:92:da:9a:33:6f:69")
}
