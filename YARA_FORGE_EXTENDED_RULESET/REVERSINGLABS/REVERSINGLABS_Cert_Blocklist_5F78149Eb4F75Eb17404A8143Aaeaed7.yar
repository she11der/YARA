import "pe"

rule REVERSINGLABS_Cert_Blocklist_5F78149Eb4F75Eb17404A8143Aaeaed7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4c9d3bba-4e7f-5bf5-ab90-f2b900ec0b2a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2788-L2804"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0c7c9e8d2a9304e0407b8a1a29977312a9ba766a4052c6b874855fa187c85585"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE4\\xB8\\x8A\\xE6\\xB5\\xB7\\xE5\\x9F\\x9F\\xE8\\x81\\x94\\xE8\\xBD\\xAF\\xE4\\xBB\\xB6\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="5f:78:14:9e:b4:f7:5e:b1:74:04:a8:14:3a:ae:ae:d7" and 1303116124<=pe.signatures[i].not_after)
}
