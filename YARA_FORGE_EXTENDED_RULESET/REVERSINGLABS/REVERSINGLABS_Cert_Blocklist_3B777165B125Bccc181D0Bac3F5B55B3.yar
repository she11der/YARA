import "pe"

rule REVERSINGLABS_Cert_Blocklist_3B777165B125Bccc181D0Bac3F5B55B3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f065e99f-9cce-55cb-a592-60b89c26028a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8714-L8730"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "80aff3d6f45f5847d5d39b170b9d0e70168d02569ca6d86a2c39150399d290fc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STAND ALONE MUSIC LTD" and pe.signatures[i].serial=="3b:77:71:65:b1:25:bc:cc:18:1d:0b:ac:3f:5b:55:b3" and 1607299200<=pe.signatures[i].not_after)
}
