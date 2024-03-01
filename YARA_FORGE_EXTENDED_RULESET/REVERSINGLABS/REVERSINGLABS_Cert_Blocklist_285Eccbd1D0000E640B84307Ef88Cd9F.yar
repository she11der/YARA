import "pe"

rule REVERSINGLABS_Cert_Blocklist_285Eccbd1D0000E640B84307Ef88Cd9F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4dc1523f-edc8-52e2-99aa-7389c0eb5e54"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15536-L15552"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "267df1c327b65938b2b82a53ec8345290659560c69c9a70f2866fe7bd73513a7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DRAGON BUSINESS EQUIPMENT LIMITED" and pe.signatures[i].serial=="28:5e:cc:bd:1d:00:00:e6:40:b8:43:07:ef:88:cd:9f" and 1611619200<=pe.signatures[i].not_after)
}
