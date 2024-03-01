import "pe"

rule REVERSINGLABS_Cert_Blocklist_Fe9404Dc73Cf1C2Ba1450B8398305557 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "17700719-81ea-58d4-87f5-4d5c1b19bf64"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2356-L2374"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c0132d71de1384f6e534dd154eba88c4a51c43b7dfe984f3064ba4feffa4dd5a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\x8E\\xA6\\xE9\\x97\\xA8\\xE7\\xBF\\x94\\xE9\\x80\\x9A\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE5\\x88\\x86\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (pe.signatures[i].serial=="00:fe:94:04:dc:73:cf:1c:2b:a1:45:0b:83:98:30:55:57" or pe.signatures[i].serial=="fe:94:04:dc:73:cf:1c:2b:a1:45:0b:83:98:30:55:57") and 1287360000<=pe.signatures[i].not_after)
}
