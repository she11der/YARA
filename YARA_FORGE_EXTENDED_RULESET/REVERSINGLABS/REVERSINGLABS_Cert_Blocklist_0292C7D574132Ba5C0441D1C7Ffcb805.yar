import "pe"

rule REVERSINGLABS_Cert_Blocklist_0292C7D574132Ba5C0441D1C7Ffcb805 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ef58cf01-9c54-5dbb-99a7-d3ca42663133"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5938-L5954"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d2bcf72f4c5829d161bc40e820eb0b1a85deaa49b749422d5429e27b7fb2b1fe"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TES LOGISTIKA d.o.o." and pe.signatures[i].serial=="02:92:c7:d5:74:13:2b:a5:c0:44:1d:1c:7f:fc:b8:05" and 1602183720<=pe.signatures[i].not_after)
}
