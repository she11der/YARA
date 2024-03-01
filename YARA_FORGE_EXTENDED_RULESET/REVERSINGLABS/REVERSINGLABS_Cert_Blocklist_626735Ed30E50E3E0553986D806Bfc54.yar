import "pe"

rule REVERSINGLABS_Cert_Blocklist_626735Ed30E50E3E0553986D806Bfc54 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e0cfc0e6-b36e-5d4e-bfe6-21f13499dc0c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11632-L11648"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0a2acf8528a12fd05cf58c2ed5224f7472d14251b342ce4df6d9c10c6a6decfc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FISH ACCOUNTING & TRANSLATING LIMITED" and pe.signatures[i].serial=="62:67:35:ed:30:e5:0e:3e:05:53:98:6d:80:6b:fc:54" and 1666742400<=pe.signatures[i].not_after)
}
