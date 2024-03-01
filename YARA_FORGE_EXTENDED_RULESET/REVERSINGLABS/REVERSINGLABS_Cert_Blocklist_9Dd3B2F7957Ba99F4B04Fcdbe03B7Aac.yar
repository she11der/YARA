import "pe"

rule REVERSINGLABS_Cert_Blocklist_9Dd3B2F7957Ba99F4B04Fcdbe03B7Aac : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "25229478-e891-5e0a-b738-6ca1fdd0012c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10314-L10332"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d4f1b75dddd47fe8a19bd8e794b4930bdcaf54d63db57422db0a9b631d4f488d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DOD MEDIA LIMITED" and (pe.signatures[i].serial=="00:9d:d3:b2:f7:95:7b:a9:9f:4b:04:fc:db:e0:3b:7a:ac" or pe.signatures[i].serial=="9d:d3:b2:f7:95:7b:a9:9f:4b:04:fc:db:e0:3b:7a:ac") and 1646438400<=pe.signatures[i].not_after)
}
