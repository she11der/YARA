import "pe"

rule REVERSINGLABS_Cert_Blocklist_53E1F226Cb77574F8Fbeb5682Da091Bb : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fe3abe27-c8c8-54b8-b031-0546c9bfda90"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11200-L11216"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "591846225d5faf3ee8f3102acaad066f0187219044077bbdaf32345613b00965"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OdyLab Inc" and pe.signatures[i].serial=="53:e1:f2:26:cb:77:57:4f:8f:be:b5:68:2d:a0:91:bb" and 1654020559<=pe.signatures[i].not_after)
}
