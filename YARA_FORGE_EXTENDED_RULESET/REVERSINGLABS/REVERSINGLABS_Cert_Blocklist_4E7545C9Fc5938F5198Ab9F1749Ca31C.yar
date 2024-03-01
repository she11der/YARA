import "pe"

rule REVERSINGLABS_Cert_Blocklist_4E7545C9Fc5938F5198Ab9F1749Ca31C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d5f810ee-127a-5df0-9299-ffeaddf369ee"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7332-L7348"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f6be57eb6744ad6d239a0a2cc1ec8c39c9dfd4e4eeb3be9e699516c259f617f0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "For M d.o.o." and pe.signatures[i].serial=="4e:75:45:c9:fc:59:38:f5:19:8a:b9:f1:74:9c:a3:1c" and 1614297600<=pe.signatures[i].not_after)
}
