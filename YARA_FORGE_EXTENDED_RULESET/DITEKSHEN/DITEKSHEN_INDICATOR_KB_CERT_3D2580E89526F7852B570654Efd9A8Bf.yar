import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3D2580E89526F7852B570654Efd9A8Bf : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "a80493e6-ed0c-597a-a87e-19c8fa8dd8ce"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L668-L679"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "19f418672850536aaac1983b45c3239d5c81c1e4b9b6ee36a761cfc7e2351531"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c1b4d57a36e0b6853dd38e3034edf7d99a8b73ad"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MIKL LIMITED" and pe.signatures[i].serial=="3d:25:80:e8:95:26:f7:85:2b:57:06:54:ef:d9:a8:bf")
}
