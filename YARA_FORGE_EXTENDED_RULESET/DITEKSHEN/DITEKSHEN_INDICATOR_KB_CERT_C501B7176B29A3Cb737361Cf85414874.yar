import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_C501B7176B29A3Cb737361Cf85414874 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8bebf02c-de14-5488-8720-5fc98b0799bd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4036-L4047"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f3eb67b39e0e4e12388f17d231fadfc2ea36b1568191a411950c2e24c32ed09c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0788801185a6bf70b805c2b97a7c6ce66cfbb38d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\x8B\\x92\\xE8\\x89\\xBE\\xE8\\xAF\\xB6\\xE8\\x89\\xBE\\xE8\\xB4\\x9D\\xE8\\xAF\\xB6\\xE8\\xAF\\xB6\\xE8\\xB4\\x9D\\xE5\\x90\\xBE\\xE5\\xBC\\x97\\xE5\\xBC\\x97\\xE5\\x90\\xBE\\xE8\\xAF\\xB6\\xE5\\x8B\\x92\\xE8\\xB4\\x9D\\xE5\\xBC\\x97\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE8\\xAF\\xB6\\xE8\\x89\\xBE\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE8\\x89\\xBE\\xE5\\xBC\\x97\\xE5\\xBC\\x97" and pe.signatures[i].serial=="c5:01:b7:17:6b:29:a3:cb:73:73:61:cf:85:41:48:74")
}
