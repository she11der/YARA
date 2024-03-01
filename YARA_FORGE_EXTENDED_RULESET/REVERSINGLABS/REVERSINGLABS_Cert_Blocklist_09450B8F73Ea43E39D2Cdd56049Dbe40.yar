import "pe"

rule REVERSINGLABS_Cert_Blocklist_09450B8F73Ea43E39D2Cdd56049Dbe40 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e6914a29-f6f7-56fc-8606-95666d31cf33"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9276-L9292"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "22b344b8befc00b0154d225603c81c6058399770f54cb6a09d0f7908c5c8188c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE4\\xB9\\x9D\\xE6\\xB1\\x9F\\xE5\\xAE\\x8F\\xE5\\x9B\\xBE\\xE6\\x97\\xA0\\xE5\\xBF\\xA7\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="09:45:0b:8f:73:ea:43:e3:9d:2c:dd:56:04:9d:be:40" and 1561602110<=pe.signatures[i].not_after)
}
