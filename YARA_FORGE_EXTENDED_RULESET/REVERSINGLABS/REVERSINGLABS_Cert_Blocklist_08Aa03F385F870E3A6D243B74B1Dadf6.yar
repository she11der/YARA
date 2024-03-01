import "pe"

rule REVERSINGLABS_Cert_Blocklist_08Aa03F385F870E3A6D243B74B1Dadf6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "64aa17fe-676d-5c6e-babc-15b5e8dc72bb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17272-L17288"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ef49a28a93d31c55dd2dfd3bec645f757a0a1a7eb8718ce92cf47bf9af126aed"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE4\\xB8\\x9C\\xE8\\x8E\\x9E\\xE5\\xB8\\x82\\xE8\\x85\\xBE\\xE4\\xBA\\x91\\xE8\\xAE\\xA1\\xE7\\xAE\\x97\\xE6\\x9C\\xBA\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and pe.signatures[i].serial=="08:aa:03:f3:85:f8:70:e3:a6:d2:43:b7:4b:1d:ad:f6" and 1352678400<=pe.signatures[i].not_after)
}
