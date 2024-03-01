import "pe"

rule REVERSINGLABS_Cert_Blocklist_B8164F7143E1A313003Ab0C834562F1F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "50d50330-4098-59dd-b2da-0714eefdfc66"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11142-L11160"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a42fec2e0e8d37948420f16907f39c3d502c535be98024d04a777dfbc633004d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ekitai Data Inc." and (pe.signatures[i].serial=="00:b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f" or pe.signatures[i].serial=="b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f") and 1598313600<=pe.signatures[i].not_after)
}
