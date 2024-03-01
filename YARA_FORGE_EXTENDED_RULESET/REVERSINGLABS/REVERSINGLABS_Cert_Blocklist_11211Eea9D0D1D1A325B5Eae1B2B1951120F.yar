import "pe"

rule REVERSINGLABS_Cert_Blocklist_11211Eea9D0D1D1A325B5Eae1B2B1951120F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "09b8b3f3-a4aa-5584-b8d0-751cc87267bf"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17034-L17050"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bafab986605be61d25a6764042937bc5d8c55196ea8ea9aa9360764d9681351b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LLC HERMES" and pe.signatures[i].serial=="11:21:1e:ea:9d:0d:1d:1a:32:5b:5e:ae:1b:2b:19:51:12:0f" and 1460147212<=pe.signatures[i].not_after)
}
