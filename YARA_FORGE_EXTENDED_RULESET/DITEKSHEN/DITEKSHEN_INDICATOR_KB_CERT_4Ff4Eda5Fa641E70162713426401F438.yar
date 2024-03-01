import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4Ff4Eda5Fa641E70162713426401F438 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "cc81ed1d-bd77-5cec-8bee-23e8ef448edc"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L824-L835"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d08e12e74e9c0b7a89ffa81a1b8595953d857e571a5b7a6947eba18bf39610f6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a6277cc8fce0f90a1909e6dac8b02a5115dafb40"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DUHANEY LIMITED" and pe.signatures[i].serial=="4f:f4:ed:a5:fa:64:1e:70:16:27:13:42:64:01:f4:38")
}
