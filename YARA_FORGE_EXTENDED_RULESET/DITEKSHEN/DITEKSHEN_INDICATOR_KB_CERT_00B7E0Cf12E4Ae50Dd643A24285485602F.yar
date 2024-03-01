import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B7E0Cf12E4Ae50Dd643A24285485602F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "d314925c-c6b2-5a7f-ba73-038ea4759149"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L889-L900"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7aefb436b7e3865b1abb6bbc3e0027a628f39e25cb4b28f35f070e000c19c1c7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "744160f36ba9b0b9277c6a71bf383f1898fd6d89"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GESO LTD" and pe.signatures[i].serial=="00:b7:e0:cf:12:e4:ae:50:dd:64:3a:24:28:54:85:60:2f")
}
