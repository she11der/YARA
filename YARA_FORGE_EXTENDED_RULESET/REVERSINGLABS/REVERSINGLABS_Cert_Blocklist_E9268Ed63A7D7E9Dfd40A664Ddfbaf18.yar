import "pe"

rule REVERSINGLABS_Cert_Blocklist_E9268Ed63A7D7E9Dfd40A664Ddfbaf18 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a93b0a98-cfec-5e32-9fd8-b3d6c4353558"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12198-L12216"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fc840c0b37867c3b0aa80d4dc609feaaab77d3f0c6f84c8bb2ea7c5a6461ebb8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Casta, s.r.o." and (pe.signatures[i].serial=="00:e9:26:8e:d6:3a:7d:7e:9d:fd:40:a6:64:dd:fb:af:18" or pe.signatures[i].serial=="e9:26:8e:d6:3a:7d:7e:9d:fd:40:a6:64:dd:fb:af:18") and 1647302400<=pe.signatures[i].not_after)
}
