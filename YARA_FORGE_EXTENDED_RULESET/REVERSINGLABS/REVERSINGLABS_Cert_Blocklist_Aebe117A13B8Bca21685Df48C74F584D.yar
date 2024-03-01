import "pe"

rule REVERSINGLABS_Cert_Blocklist_Aebe117A13B8Bca21685Df48C74F584D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ec525737-9770-585e-922a-43f14e0a4a37"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7012-L7030"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e7fbc1f32adec39c94dc046933e152cd6d3946da4a168306484b7b6bc7f26fb6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NANAX d.o.o." and (pe.signatures[i].serial=="00:ae:be:11:7a:13:b8:bc:a2:16:85:df:48:c7:4f:58:4d" or pe.signatures[i].serial=="ae:be:11:7a:13:b8:bc:a2:16:85:df:48:c7:4f:58:4d") and 1613520000<=pe.signatures[i].not_after)
}
