import "pe"

rule REVERSINGLABS_Cert_Blocklist_0A466553A6391Aafd181B400266C7B18 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ef8ff250-840f-5b55-b0c7-85ca54aadc59"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13240-L13256"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cb21e5759887904d6a38cd1b363610ebc0bfd9a357050c602210468992815cbe"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PhaseQ Limited" and pe.signatures[i].serial=="0a:46:65:53:a6:39:1a:af:d1:81:b4:00:26:6c:7b:18" and 1555545600<=pe.signatures[i].not_after)
}
