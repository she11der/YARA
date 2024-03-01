import "pe"

rule REVERSINGLABS_Cert_Blocklist_038D56A12153E8B5C74C69Bff65Cbe3F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "48162554-a95b-5cd3-9bbb-bcf6a1d96592"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9384-L9400"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ed3a81231f93f9d2ae462481503ba37072c3800dd1379baae11737f093a27af1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\xAD\\xA6\\xE6\\xB1\\x89\\xE5\\x86\\x85\\xE7\\x91\\x9F\\xE6\\x96\\xAF\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="03:8d:56:a1:21:53:e8:b5:c7:4c:69:bf:f6:5c:be:3f" and 1605680260<=pe.signatures[i].not_after)
}
