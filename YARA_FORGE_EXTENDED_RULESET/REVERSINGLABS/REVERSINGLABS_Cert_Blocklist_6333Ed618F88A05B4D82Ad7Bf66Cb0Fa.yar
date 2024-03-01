import "pe"

rule REVERSINGLABS_Cert_Blocklist_6333Ed618F88A05B4D82Ad7Bf66Cb0Fa : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c4d3603e-57e2-57df-a055-c43d449242c7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8696-L8712"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b088ac4b74a8cf3dddb67c8de2b7c3c5f537287a0454c0030c0eb4069c465c7d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RHM LIMITED" and pe.signatures[i].serial=="63:33:ed:61:8f:88:a0:5b:4d:82:ad:7b:f6:6c:b0:fa" and 1616457600<=pe.signatures[i].not_after)
}
