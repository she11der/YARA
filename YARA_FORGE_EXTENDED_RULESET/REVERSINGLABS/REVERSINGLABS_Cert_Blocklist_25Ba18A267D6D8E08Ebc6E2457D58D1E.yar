import "pe"

rule REVERSINGLABS_Cert_Blocklist_25Ba18A267D6D8E08Ebc6E2457D58D1E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "eb06576e-11ea-58ba-aa19-68c161f6aa68"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10788-L10804"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "174fe170c26a8197486e7b390d9fce4da61fb68ee5dc9486d43dbeb3cf659c3a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "5Y TECHNOLOGY LIMITED" and pe.signatures[i].serial=="25:ba:18:a2:67:d6:d8:e0:8e:bc:6e:24:57:d5:8d:1e" and 1648684800<=pe.signatures[i].not_after)
}
