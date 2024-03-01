import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ede6Cfbf9Fa18337B0Fdb49C1F693020 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "f1f34147-132e-53a3-b82c-d98121fc3f2c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L746-L757"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "27f06a7a07b818fd34f5d23fd8e78f041063e035c1f8caa99aaaf53ec73a717a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a99b52e0999990c2eb24d1309de7d4e522937080"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "START ARCHITECTURE LTD" and pe.signatures[i].serial=="00:ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20")
}
