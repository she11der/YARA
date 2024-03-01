import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1Afd1491D52F89Ba41Fa6C0281Bb9716 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a0e5569f-7895-519b-9c1b-9cea3126391f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5513-L5524"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "071895cc37527aa634410dc79bf1656068e4c2b9f61d24912160c5f847e154f9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e4362228dd69c25c1d4ba528549fa00845a8dc24"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TestCert" and pe.signatures[i].serial=="1a:fd:14:91:d5:2f:89:ba:41:fa:6c:02:81:bb:97:16")
}
