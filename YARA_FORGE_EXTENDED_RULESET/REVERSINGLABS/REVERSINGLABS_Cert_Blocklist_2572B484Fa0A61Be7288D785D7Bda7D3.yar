import "pe"

rule REVERSINGLABS_Cert_Blocklist_2572B484Fa0A61Be7288D785D7Bda7D3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b1d71baa-9100-512d-91f4-7286a740e5f2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14602-L14618"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d6b23ba706a640a1e76ad7ab0a70c845c9366ac8355eea5439f76f6993c9c6be"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SILVA, OOO" and pe.signatures[i].serial=="25:72:b4:84:fa:0a:61:be:72:88:d7:85:d7:bd:a7:d3" and 1495152000<=pe.signatures[i].not_after)
}
