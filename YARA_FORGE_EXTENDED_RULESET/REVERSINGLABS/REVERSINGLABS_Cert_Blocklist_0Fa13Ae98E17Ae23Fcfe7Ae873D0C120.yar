import "pe"

rule REVERSINGLABS_Cert_Blocklist_0Fa13Ae98E17Ae23Fcfe7Ae873D0C120 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "87a47456-4d90-5a7d-af9d-7a6d5fb8efac"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5310-L5326"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "415f39f82b6a45acd196ccf246ec660806a8d66c61df8c7d2850e5b244118d04"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KLAKSON, LLC" and pe.signatures[i].serial=="0f:a1:3a:e9:8e:17:ae:23:fc:fe:7a:e8:73:d0:c1:20" and 1597276801<=pe.signatures[i].not_after)
}
