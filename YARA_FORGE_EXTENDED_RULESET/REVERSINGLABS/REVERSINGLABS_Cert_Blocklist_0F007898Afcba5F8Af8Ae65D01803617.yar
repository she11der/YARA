import "pe"

rule REVERSINGLABS_Cert_Blocklist_0F007898Afcba5F8Af8Ae65D01803617 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6678bd73-bf4d-5576-8bf2-b721ee288da7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10032-L10048"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "27610bb3bf069991803611474abf44a3bf82fc9283d0412a1c24ae46a3f5352e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TechnoElek s.r.o." and pe.signatures[i].serial=="0f:00:78:98:af:cb:a5:f8:af:8a:e6:5d:01:80:36:17" and 1638372946<=pe.signatures[i].not_after)
}
