import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Cc37De5Dbed097F98F56Dbc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8c362133-a30f-599d-88e0-a1448433178a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15260-L15276"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a2d04275b9fe37308c8f1dca75f4cc3c4a8985930f901e1f46e3ddc2977eea32"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="1c:c3:7d:e5:db:ed:09:7f:98:f5:6d:bc" and 1476693977<=pe.signatures[i].not_after)
}
