import "pe"

rule REVERSINGLABS_Cert_Blocklist_5F8203C430Fc7Db4E61F6684F6829Ffc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "975cd500-2f08-55c9-a821-4dde3a54ae0c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2506-L2522"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cd22d1beea12d1f6c50f69e76074c2582ce5567887056c43d4d6c87d33fce1bf"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Haivision Network Video" and pe.signatures[i].serial=="5f:82:03:c4:30:fc:7d:b4:e6:1f:66:84:f6:82:9f:fc" and 1382572799<=pe.signatures[i].not_after)
}
