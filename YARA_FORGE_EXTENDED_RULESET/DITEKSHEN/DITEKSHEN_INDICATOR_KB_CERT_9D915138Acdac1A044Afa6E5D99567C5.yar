import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_9D915138Acdac1A044Afa6E5D99567C5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "89182dfb-b100-573c-85ae-38bdf7f24a64"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5591-L5602"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "32fb0d12a9b61461104e29571fcc7210f7ea8a82a8e240c747a0070d8d43a9b0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4f8b9ce0e25810d1b62d8c016607de128beba2a1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AAAruntest" and pe.signatures[i].serial=="9d:91:51:38:ac:da:c1:a0:44:af:a6:e5:d9:95:67:c5")
}
