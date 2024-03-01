import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_009356E0361Bcf983Ab14276C332F814E7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "6b5966d7-59ab-5d8a-936e-71b937424234"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1205-L1216"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e85adfa9c004a46fe6060a36def3f8387de1484eb9fc3ae935d00265da135eab"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f8bc145719666175a2bb3fcc62e0f3b2deccb030"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xE5\\x90\\x89\\xE4\\xB8\\x9D\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE4\\xB8\\x9D\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A\\xE6\\x9D\\xB0\\xE5\\x90\\x89\\xE4\\xBC\\x8A" and pe.signatures[i].serial=="00:93:56:e0:36:1b:cf:98:3a:b1:42:76:c3:32:f8:14:e7")
}
