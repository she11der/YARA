import "pe"

rule REVERSINGLABS_Cert_Blocklist_476Bf24A4B1E9F4Bc2A61B152115E1Fe : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing Derusbi malware."
		author = "ReversingLabs"
		id = "a41e8196-f5ad-5046-82ac-38c6fe753bdb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2014-L2030"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0ec0f44d2a7a53ad5653334378b631abde1834ebfcf72efcdcce353c6b9ae17d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Wemade Entertainment co.,Ltd" and pe.signatures[i].serial=="47:6b:f2:4a:4b:1e:9f:4b:c2:a6:1b:15:21:15:e1:fe" and 1414454399<=pe.signatures[i].not_after)
}
