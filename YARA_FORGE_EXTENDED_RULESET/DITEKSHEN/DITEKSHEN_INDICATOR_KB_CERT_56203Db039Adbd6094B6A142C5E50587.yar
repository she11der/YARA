import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_56203Db039Adbd6094B6A142C5E50587 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "b3e56f78-e79a-52e3-b29e-1f566946609e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3-L14"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "38380bc1a22b8d0fe851f76d2ecadba638f10b01873be44766124fb738e23d71"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e438c77483ecab0ff55cc31f2fd2f835958fad80"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bccabdacabbdcda" and pe.signatures[i].serial=="56:20:3d:b0:39:ad:bd:60:94:b6:a1:42:c5:e5:05:87")
}
