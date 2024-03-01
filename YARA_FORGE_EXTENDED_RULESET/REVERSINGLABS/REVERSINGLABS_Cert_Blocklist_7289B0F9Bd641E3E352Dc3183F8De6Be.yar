import "pe"

rule REVERSINGLABS_Cert_Blocklist_7289B0F9Bd641E3E352Dc3183F8De6Be : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dc8a745f-7150-57b7-9ddc-e5a1721d8c02"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3082-L3098"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "42b068e85b3aff5e6dd5ec4979f546dc5338ebf8719d86c0641ffb8353959af9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ICE ACTIVATION LIMITED" and pe.signatures[i].serial=="72:89:b0:f9:bd:64:1e:3e:35:2d:c3:18:3f:8d:e6:be" and 1557933274<=pe.signatures[i].not_after)
}
