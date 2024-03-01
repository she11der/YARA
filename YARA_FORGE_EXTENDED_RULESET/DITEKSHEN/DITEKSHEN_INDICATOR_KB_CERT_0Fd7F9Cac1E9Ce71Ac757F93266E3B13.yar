import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Fd7F9Cac1E9Ce71Ac757F93266E3B13 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "6021f566-e297-5af4-b692-663480091296"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7445-L7457"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "319f858a15f8752d7637ab7036ed89b17c501c2422769339578e685fe6a57eea"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "af2779ceb127caa6c22232ad359888a0a71ce221"
		hash1 = "7c28b994aeb3a85e37225cc20bae2232f97e23f115c2a409da31f353140c631e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE9\\x9D\\x92\\xE5\\xB2\\x9B\\xE4\\xB8\\x89\\xE5\\x96\\x9C\\xE8\\xB4\\xB8\\xE6\\x98\\x93\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="0f:d7:f9:ca:c1:e9:ce:71:ac:75:7f:93:26:6e:3b:13")
}
