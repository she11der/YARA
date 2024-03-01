import "pe"

rule REVERSINGLABS_Cert_Blocklist_B514E4C5309Ef9F27Add05Bedd4339A0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4b5abcfe-259e-5029-822b-c191b8d2c607"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5616-L5634"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "665b280218528bbe3d5c65d043266469e5288587ed9d85d01797bef7ce132a6f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SCABONE PTY LTD" and (pe.signatures[i].serial=="00:b5:14:e4:c5:30:9e:f9:f2:7a:dd:05:be:dd:43:39:a0" or pe.signatures[i].serial=="b5:14:e4:c5:30:9e:f9:f2:7a:dd:05:be:dd:43:39:a0") and 1572566400<=pe.signatures[i].not_after)
}
