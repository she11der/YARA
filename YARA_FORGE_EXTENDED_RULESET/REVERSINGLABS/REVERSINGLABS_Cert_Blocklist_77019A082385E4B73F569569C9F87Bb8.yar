import "pe"

rule REVERSINGLABS_Cert_Blocklist_77019A082385E4B73F569569C9F87Bb8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4046a31b-d7c8-5c63-b5b2-2179b0817b03"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L45-L61"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8613986005bdd30d92e633fa2058be5c43f1c530b9dc6d80ec953f12f6d66ce7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AND LLC" and pe.signatures[i].serial=="77:01:9a:08:23:85:e4:b7:3f:56:95:69:c9:f8:7b:b8" and 1308182400<=pe.signatures[i].not_after)
}
