import "pe"

rule REVERSINGLABS_Cert_Blocklist_Eda0F47B3B38E781Cdf6Ef6Be5D3F6Ee : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "308a73cd-a142-56ad-8dca-808ab455b43e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16436-L16454"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "af3cd543a6feec3118ba4e5fdc8455584aa763bd8339f036ab332977fc0fb20e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ADVANCED ACCESS SERVICES LTD" and (pe.signatures[i].serial=="00:ed:a0:f4:7b:3b:38:e7:81:cd:f6:ef:6b:e5:d3:f6:ee" or pe.signatures[i].serial=="ed:a0:f4:7b:3b:38:e7:81:cd:f6:ef:6b:e5:d3:f6:ee") and 1650931200<=pe.signatures[i].not_after)
}
