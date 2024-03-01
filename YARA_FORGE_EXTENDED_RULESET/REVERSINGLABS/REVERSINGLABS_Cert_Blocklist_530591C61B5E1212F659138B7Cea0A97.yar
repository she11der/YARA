import "pe"

rule REVERSINGLABS_Cert_Blocklist_530591C61B5E1212F659138B7Cea0A97 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "71cf0653-5aab-5d5c-aa3a-f42f40196412"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L747-L763"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0ef01e542d145475713bbd373bdcdae5f25bfd823a60e7d40fe9a6b6039c83e0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\x97\\xA5\\xE7\\x85\\xA7\\xE5\\xB3\\xB0\\xE5\\xB7\\x9D\\xE5\\x9B\\xBD\\xE9\\x99\\x85\\xE7\\x9F\\xBF\\xE4\\xB8\\x9A\\xE8\\xB4\\xB8\\xE6\\x98\\x93\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="53:05:91:c6:1b:5e:12:12:f6:59:13:8b:7c:ea:0a:97" and 1403654399<=pe.signatures[i].not_after)
}
