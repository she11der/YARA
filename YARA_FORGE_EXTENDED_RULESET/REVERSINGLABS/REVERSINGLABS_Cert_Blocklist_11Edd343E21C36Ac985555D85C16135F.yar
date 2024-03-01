import "pe"

rule REVERSINGLABS_Cert_Blocklist_11Edd343E21C36Ac985555D85C16135F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "219f709f-4e05-5d0e-97a4-eca1e65153a3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4050-L4066"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "17feeed4be074a30572eb12fc81dc15d1b06f2d3f7b4b4fb4443391c62ac4d9b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pribyl Handels GmbH" and pe.signatures[i].serial=="11:ed:d3:43:e2:1c:36:ac:98:55:55:d8:5c:16:13:5f" and 1589925600<=pe.signatures[i].not_after)
}
