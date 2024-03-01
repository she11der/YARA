import "pe"

rule REVERSINGLABS_Cert_Blocklist_936Bc256D2057Ca9B9Ec3034C3Ed0Ee6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4dbe7db7-2f61-558c-a6dc-875ba87322c7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9572-L9590"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7e90c29bcfe4632e70b61a0cf2ab48a3de986bd5c6c730f64a363f4f3d79a3f4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SALES & MAINTENANCE LIMITED" and (pe.signatures[i].serial=="00:93:6b:c2:56:d2:05:7c:a9:b9:ec:30:34:c3:ed:0e:e6" or pe.signatures[i].serial=="93:6b:c2:56:d2:05:7c:a9:b9:ec:30:34:c3:ed:0e:e6") and 1616889600<=pe.signatures[i].not_after)
}
