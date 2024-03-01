import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4C8Def294478B7D59Ee95C61Fae3D965 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "2f95a688-2fb2-55b7-9cd5-44586d6d4dc8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L185-L196"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d9e956d7d5b9389aebafd4b7025818ac8eb5a72aaa1b94068a12aa7a8029f97c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = ""
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DREAM SECURITY USA INC" and pe.signatures[i].serial=="4c:8d:ef:29:44:78:b7:d5:9e:e9:5c:61:fa:e3:d9:65")
}
