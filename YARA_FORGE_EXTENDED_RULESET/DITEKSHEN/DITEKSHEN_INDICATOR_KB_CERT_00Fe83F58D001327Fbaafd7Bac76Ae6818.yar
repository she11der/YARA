import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Fe83F58D001327Fbaafd7Bac76Ae6818 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5d41be99-85de-55bc-817b-eea510aff308"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7237-L7251"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "8aac715daba042ca4a57cd65b98e6192c87a13e7e0c8ff4a3bc81c43223035ad"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c130dd74928da75a42e9d32a1d3f2fd860d81566"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "A. Jensen FLY Fishing ApS" and (pe.signatures[i].serial=="fe:83:f5:8d:00:13:27:fb:aa:fd:7b:ac:76:ae:68:18" or pe.signatures[i].serial=="00:fe:83:f5:8d:00:13:27:fb:aa:fd:7b:ac:76:ae:68:18"))
}
