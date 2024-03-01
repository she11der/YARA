import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6Cfa5050C819C4Acbb8Fa75979688Dff : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "35673979-5578-5d32-b8f9-9e74f0c336a2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1452-L1463"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e5978deb84a0c6cee9132f8806f239f33478462da31a423a04922c195cbd343a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e7241394097402bf9e32c87cada4ba5e0d1e9923f028683713c2f339f6f59fa9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Elite Web Development Ltd." and pe.signatures[i].serial=="6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff")
}
