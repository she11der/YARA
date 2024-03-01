import "pe"

rule REVERSINGLABS_Cert_Blocklist_24E4A2B3Db6Be1007B9Ddc91995Bc0C8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8e533ebf-a124-53a9-8647-6f4b40aaa066"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11162-L11178"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "861691ce7bae4366f3b35d01c84bb0031b54653869f52eaccf20808b1b55d2af"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FLY BETTER s.r.o." and pe.signatures[i].serial=="24:e4:a2:b3:db:6b:e1:00:7b:9d:dc:91:99:5b:c0:c8" and 1645142400<=pe.signatures[i].not_after)
}
