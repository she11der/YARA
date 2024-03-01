import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_E5Bf5B5C0880Db96477C24C18519B9B9 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "a28dbf8f-1b30-525d-baaf-51342aaf1cb3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L733-L744"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b3e0401a9cf3005abac24114193f34bf439107bf6661b7c2c0b66ca91438c7b9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = ""
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WATWGHFC" and pe.signatures[i].serial=="e5:bf:5b:5c:08:80:db:96:47:7c:24:c1:85:19:b9:b9")
}
