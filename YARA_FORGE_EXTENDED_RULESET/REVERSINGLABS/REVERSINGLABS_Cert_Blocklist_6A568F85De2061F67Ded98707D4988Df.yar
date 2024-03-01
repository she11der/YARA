import "pe"

rule REVERSINGLABS_Cert_Blocklist_6A568F85De2061F67Ded98707D4988Df : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "962c3096-2c3d-5137-9637-b45d00b2ee9b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7616-L7632"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "793be308a4df55c3b325e1ee3185159c4155f6dfabc311216d3763bd43680bd4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Apladis" and pe.signatures[i].serial=="6a:56:8f:85:de:20:61:f6:7d:ed:98:70:7d:49:88:df" and 1613001600<=pe.signatures[i].not_after)
}
