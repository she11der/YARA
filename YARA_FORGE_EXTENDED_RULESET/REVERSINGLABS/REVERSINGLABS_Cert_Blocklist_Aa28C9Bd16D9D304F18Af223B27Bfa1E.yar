import "pe"

rule REVERSINGLABS_Cert_Blocklist_Aa28C9Bd16D9D304F18Af223B27Bfa1E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "facb8bba-a8cc-5b2a-9ef6-ba290cbf9b24"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7484-L7502"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "feaa8d645eea46c7cbbba4ba86c92184df7515a50f1f905ab818c59079a0c96a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Tecno trade d.o.o." and (pe.signatures[i].serial=="00:aa:28:c9:bd:16:d9:d3:04:f1:8a:f2:23:b2:7b:fa:1e" or pe.signatures[i].serial=="aa:28:c9:bd:16:d9:d3:04:f1:8a:f2:23:b2:7b:fa:1e") and 1611705600<=pe.signatures[i].not_after)
}
