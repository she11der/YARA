import "pe"

rule REVERSINGLABS_Cert_Blocklist_123A5074069162F4Ed68Fc7D48F464C2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "601ddd98-8cd5-5c52-a59a-d4a0556fc316"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15720-L15736"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f55835c7404edab96bc5c8fe3844f3380f1f6bc8b43da1d51213de899629e8f5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="12:3a:50:74:06:91:62:f4:ed:68:fc:7d:48:f4:64:c2" and 1472428800<=pe.signatures[i].not_after)
}
