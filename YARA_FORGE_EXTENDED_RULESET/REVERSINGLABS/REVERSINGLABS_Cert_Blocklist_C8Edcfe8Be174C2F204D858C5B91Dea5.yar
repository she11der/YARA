import "pe"

rule REVERSINGLABS_Cert_Blocklist_C8Edcfe8Be174C2F204D858C5B91Dea5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "92baa26f-1352-53ed-bb9f-0a632e471dd5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7882-L7900"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b3e6927abfce69548374bfd430a3ae3a1c5a8d05f0f40e43091b4d12025c5b1a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Paarcopy Oy" and (pe.signatures[i].serial=="00:c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5" or pe.signatures[i].serial=="c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5") and 1608076800<=pe.signatures[i].not_after)
}
