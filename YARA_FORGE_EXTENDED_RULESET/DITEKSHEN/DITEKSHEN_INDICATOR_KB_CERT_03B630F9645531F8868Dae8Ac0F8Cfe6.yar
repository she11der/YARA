import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_03B630F9645531F8868Dae8Ac0F8Cfe6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "ca5203b8-3029-5914-b611-1717aefc7ccf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L289-L300"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "0c388ee7cfc2f35d5e020520d0c5a04b872d5deff63fc551308168e60122f7fc"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ab027825daf46c5e686e4d9bc9c55a5d8c5e957d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Geksan LLC" and pe.signatures[i].serial=="03:b6:30:f9:64:55:31:f8:86:8d:ae:8a:c0:f8:cf:e6")
}
