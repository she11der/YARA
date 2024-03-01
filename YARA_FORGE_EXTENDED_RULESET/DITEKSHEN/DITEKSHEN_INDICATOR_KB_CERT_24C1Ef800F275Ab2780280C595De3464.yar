import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_24C1Ef800F275Ab2780280C595De3464 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0bd14ac3-9761-5ac4-8cdc-6212a92c5b5d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5910-L5921"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "773fdb6d15a5bd1282dd9a48601b453b62de2e9832822858ad750c6462d6e116"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "836b81154eb924fe741f50a21db258da9b264b85"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HOLGAN LIMITED" and pe.signatures[i].serial=="24:c1:ef:80:0f:27:5a:b2:78:02:80:c5:95:de:34:64")
}
