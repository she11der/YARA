import "pe"

rule REVERSINGLABS_Cert_Blocklist_6Ac6268B2E431A2C1369346D175D0E30 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "12664460-19e1-5b73-8299-cfe19dffc0b4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12800-L12816"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "27efaba9bd9cd116f640007c1e951bb77757efbe148b5f953e71d6621d7f16b2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Install Sync" and pe.signatures[i].serial=="6a:c6:26:8b:2e:43:1a:2c:13:69:34:6d:17:5d:0e:30" and 1436140800<=pe.signatures[i].not_after)
}
