import "pe"

rule REVERSINGLABS_Cert_Blocklist_21Bfddb6A66435D1Adce2Ceb23Ed7C9A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2009c47b-8a15-50fd-a229-5e34244ede1f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17088-L17104"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "22ad68974a1c6729da369c26372ba93c25ddf68df880580c727bf2d3ee2d3a86"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE6\\x9D\\xA8\\xE6\\xB7\\x87\\xE6\\x99\\xBA" and pe.signatures[i].serial=="21:bf:dd:b6:a6:64:35:d1:ad:ce:2c:eb:23:ed:7c:9a" and 1395297334<=pe.signatures[i].not_after)
}
