import "pe"

rule REVERSINGLABS_Cert_Blocklist_7B75C6B0A09Afdb9787F6Dff75Ae7844 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0b34c7ce-fa75-5340-a473-fa87fab93b86"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13764-L13780"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8fd125a526b3433fbb8a5c6fa74ce0b0e2de8ff789880c355625d4140cd902a2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yuanyuan Zhang" and pe.signatures[i].serial=="7b:75:c6:b0:a0:9a:fd:b9:78:7f:6d:ff:75:ae:78:44" and 1476662400<=pe.signatures[i].not_after)
}
