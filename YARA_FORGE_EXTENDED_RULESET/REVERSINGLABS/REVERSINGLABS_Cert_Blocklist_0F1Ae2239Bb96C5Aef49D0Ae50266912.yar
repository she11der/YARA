import "pe"

rule REVERSINGLABS_Cert_Blocklist_0F1Ae2239Bb96C5Aef49D0Ae50266912 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "44c878ab-75b2-5cd3-a019-94982a508e0f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10716-L10732"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4f88df4fc2f4cd89aa177ce09caab3e2660267ae883f7ab54c22a9ba1657bad0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aarav Consulting Inc." and pe.signatures[i].serial=="0f:1a:e2:23:9b:b9:6c:5a:ef:49:d0:ae:50:26:69:12" and 1653004800<=pe.signatures[i].not_after)
}
