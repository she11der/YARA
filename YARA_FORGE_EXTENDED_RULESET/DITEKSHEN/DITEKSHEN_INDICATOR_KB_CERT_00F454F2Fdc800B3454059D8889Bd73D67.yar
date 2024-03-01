import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00F454F2Fdc800B3454059D8889Bd73D67 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "277ac503-91c4-5266-b8a4-c01a48b8df4d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7414-L7429"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "91b33a3e915a007d00482905471e124045a373fef9c8b0fe9a987196d2ec013a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2b560fabc34e0db81dae1443b1c4929eef820266"
		hash1 = "e58b80e4738dc03f5aa82d3a40a6d2ace0d7c7cfd651f1dd10df76d43d8c0eb3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BEAUTY CORP SRL" and (pe.signatures[i].serial=="f4:54:f2:fd:c8:00:b3:45:40:59:d8:88:9b:d7:3d:67" or pe.signatures[i].serial=="00:f4:54:f2:fd:c8:00:b3:45:40:59:d8:88:9b:d7:3d:67"))
}
