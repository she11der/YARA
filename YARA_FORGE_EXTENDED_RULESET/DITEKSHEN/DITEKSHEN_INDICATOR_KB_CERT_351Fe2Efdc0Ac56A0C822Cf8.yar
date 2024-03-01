import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_351Fe2Efdc0Ac56A0C822Cf8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "dcd82e7a-f235-5ff6-805b-0da7e0c0e385"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L341-L352"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a661adcd9366da7eab0aa8059bbe6236022f7513996603eb06c43a0b38ff4b85"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4230bca4b7e4744058a7bb6e355346ff0bbeb26f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Logika OOO" and pe.signatures[i].serial=="35:1f:e2:ef:dc:0a:c5:6a:0c:82:2c:f8")
}
