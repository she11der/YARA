import "pe"

rule REVERSINGLABS_Cert_Blocklist_672D4428450Afcc24Fc60969A5063A3E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "fcd8e808-dbd6-5903-868a-0aa4541e6321"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4686-L4702"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8f5927e96109184bad7de4513994fd1021fe1cc5977e60fa72d808df95cb4516"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MEP, OOO" and pe.signatures[i].serial=="67:2d:44:28:45:0a:fc:c2:4f:c6:09:69:a5:06:3a:3e" and 1597381260<=pe.signatures[i].not_after)
}
