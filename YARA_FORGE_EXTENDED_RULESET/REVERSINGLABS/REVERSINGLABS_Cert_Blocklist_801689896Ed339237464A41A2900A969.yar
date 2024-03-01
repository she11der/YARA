import "pe"

rule REVERSINGLABS_Cert_Blocklist_801689896Ed339237464A41A2900A969 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "0ef4ce5c-b2a1-59e8-8d39-3cf7ab9fd0e1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7240-L7258"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a371092cbf5a1a0c8051ba2b4c9dd758d829a2f0c21c86d1920164a0ae7751e6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GLG Rental ApS" and (pe.signatures[i].serial=="00:80:16:89:89:6e:d3:39:23:74:64:a4:1a:29:00:a9:69" or pe.signatures[i].serial=="80:16:89:89:6e:d3:39:23:74:64:a4:1a:29:00:a9:69") and 1615507200<=pe.signatures[i].not_after)
}
