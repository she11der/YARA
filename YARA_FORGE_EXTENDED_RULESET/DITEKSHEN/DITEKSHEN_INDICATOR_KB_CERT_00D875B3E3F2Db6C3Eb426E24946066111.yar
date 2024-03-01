import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D875B3E3F2Db6C3Eb426E24946066111 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a44cde8b-904b-5f1a-8cdb-4a8b16a42669"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3477-L3488"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "470424bf28b723063be5d6801ee27b0f3748b761f9005616dcab4bd864db5463"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d27211a59dc8a4b3073d116621b6857c3d70ed04"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kubit LLC" and pe.signatures[i].serial=="00:d8:75:b3:e3:f2:db:6c:3e:b4:26:e2:49:46:06:61:11")
}
