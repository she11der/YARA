import "pe"

rule REVERSINGLABS_Cert_Blocklist_0448Ec8D26597F99912138500Cc41C1B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0c306a1f-e810-5988-a44c-964b6a67c918"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9348-L9364"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "001556c31cfb0d94978adc48dc0d24c83666512348c65508975cc9e1a119aeae"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\xA4\\xA7\\xE8\\xBF\\x9E\\xE7\\xBA\\xB5\\xE6\\xA2\\xA6\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="04:48:ec:8d:26:59:7f:99:91:21:38:50:0c:c4:1c:1b" and 1585108595<=pe.signatures[i].not_after)
}
