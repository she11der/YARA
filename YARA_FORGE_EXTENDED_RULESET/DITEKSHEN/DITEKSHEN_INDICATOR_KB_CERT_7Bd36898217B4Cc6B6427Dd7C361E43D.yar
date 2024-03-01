import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7Bd36898217B4Cc6B6427Dd7C361E43D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "ff5be4ad-9471-5d9f-a1ad-ed7aca345a7f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1309-L1320"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9ff149b5a12e154c0ede5015a0432fb70d6001507356c006952e8db91afaa72d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c55df31aa16adb1013612ceb1dcf587afb7832c3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aeafefcafbafbaf" and pe.signatures[i].serial=="7b:d3:68:98:21:7b:4c:c6:b6:42:7d:d7:c3:61:e4:3d")
}
