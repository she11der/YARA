import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_A596Fd2779E507Aa466D159706Fe4150 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "8cf28e2a-d90f-5bf6-b746-7f46e8f6aa2a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L562-L573"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b88f346175e9084fdba94b9a8cbbf28a5012d28ab43350d927aac099921ab1a3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "104c4183e248d63a6e2ad6766927b070c81afcb6"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ClamAV" and pe.signatures[i].serial=="a5:96:fd:27:79:e5:07:aa:46:6d:15:97:06:fe:41:50")
}
