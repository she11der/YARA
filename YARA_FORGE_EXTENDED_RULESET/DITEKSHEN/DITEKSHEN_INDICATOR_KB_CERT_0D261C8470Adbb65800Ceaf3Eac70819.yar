import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0D261C8470Adbb65800Ceaf3Eac70819 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "0304b3ae-6a3c-5831-a749-76432b3356b4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7643-L7655"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e71f5d24500ac202aad5a439aa0d5f1bf7e6259c1d7e11bb40c7b9ae93bd86c0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "307ef8a02a0fc9032591c624624fa3531c235aa1"
		hash1 = "050dbd816c222d3c012ba9f2b1308db8e160e7d891f231272f1eacf19d0a0a06"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bandicam Company Corp." and pe.signatures[i].serial=="0d:26:1c:84:70:ad:bb:65:80:0c:ea:f3:ea:c7:08:19")
}
