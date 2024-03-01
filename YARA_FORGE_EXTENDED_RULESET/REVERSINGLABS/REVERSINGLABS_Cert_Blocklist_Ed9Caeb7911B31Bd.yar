import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ed9Caeb7911B31Bd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1eeff730-c2ce-5689-a8cb-455618738a82"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14148-L14166"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "02cfdf883212387a465af3e692b29b8d0eb8249e0a260f18bec2f662d775b606"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE4\\xB8\\x8A\\xE6\\xB5\\xB7\\xE5\\xA4\\xA9\\xE6\\xB8\\xB8\\xE8\\xBD\\xAF\\xE4\\xBB\\xB6\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (pe.signatures[i].serial=="00:ed:9c:ae:b7:91:1b:31:bd" or pe.signatures[i].serial=="ed:9c:ae:b7:91:1b:31:bd") and 1506001740<=pe.signatures[i].not_after)
}
