import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_29F2093E925B7Fe70A9Ba7B909415251 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "51c21421-18e4-52df-8fe7-75db7141824c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1244-L1255"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9b3c6a0571c096e431594d9331b3ae8127b02cc3cdf1e994a113026d77bbae4c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f9fc647988e667ec92bdf1043ea1077da8f92ccc"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xD0\\x99\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A\\xE5\\x85\\x8B\\xD0\\x99\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x99\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xE4\\xB8\\x9D\\xD0\\x99\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xD0\\x9D\\xE8\\x89\\xBE\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A" and pe.signatures[i].serial=="29:f2:09:3e:92:5b:7f:e7:0a:9b:a7:b9:09:41:52:51")
}
