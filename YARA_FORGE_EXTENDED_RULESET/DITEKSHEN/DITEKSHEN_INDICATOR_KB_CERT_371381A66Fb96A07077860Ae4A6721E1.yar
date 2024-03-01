import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_371381A66Fb96A07077860Ae4A6721E1 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "cd9c9965-922c-5ced-839c-97d1dcde33ff"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1283-L1294"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f087df37fdb6d921f411f130f26f9b5a58c36ae163bc88565178e0ed12be79d9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c4419f095ae93d93e145d678ed31459506423d6a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE7\\xBB\\xB4\\xD0\\xA9\\xE5\\x90\\xBE\\xE7\\xBB\\xB4\\xD0\\xA9\\xD0\\xA9\\xE7\\xBB\\xB4\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xD0\\xA9\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xD0\\xA9\\xE5\\xA8\\x9C\\xE6\\x9D\\xB0\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xE5\\xA8\\x9C\\xE5\\xA8\\x9C\\xD0\\xA9" and pe.signatures[i].serial=="37:13:81:a6:6f:b9:6a:07:07:78:60:ae:4a:67:21:e1")
}
