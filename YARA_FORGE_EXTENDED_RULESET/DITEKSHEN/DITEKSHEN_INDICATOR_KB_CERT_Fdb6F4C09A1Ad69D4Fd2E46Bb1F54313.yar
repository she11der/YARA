import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Fdb6F4C09A1Ad69D4Fd2E46Bb1F54313 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "e1250c37-fa89-5b8e-bea2-3b5e14039aea"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L720-L731"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ce78ab52d8aeb87ada9cb86007907a8ad46e91982cc8fff43a61e7ec96609eb2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4d1bc69003b1b1c3d0b43f6c17f81d13e0846ea7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FDSMMCME" and pe.signatures[i].serial=="fd:b6:f4:c0:9a:1a:d6:9d:4f:d2:e4:6b:b1:f5:43:13")
}
