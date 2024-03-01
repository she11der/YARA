import "pe"

rule REVERSINGLABS_Cert_Blocklist_052242Ace583Adf2A3B96Adcb04D0812 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "22104929-e2c5-565c-975c-826f666e78e2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4252-L4268"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e1593a2bf375912e411d5f19d9e232c6b87f0897bb6f1c0b0539380b34b05af5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FAN-CHAI, TOV" and pe.signatures[i].serial=="05:22:42:ac:e5:83:ad:f2:a3:b9:6a:dc:b0:4d:08:12" and 1573603200<=pe.signatures[i].not_after)
}
