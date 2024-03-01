import "pe"

rule REVERSINGLABS_Cert_Blocklist_211B5Dfe65Bc6F34Bc9D3A54 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5181b6e4-6a25-58f6-88c5-0eae98250648"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14986-L15002"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cf2e4c0dd98efb77c28b63641196c83e60afc0d6ab64802743c351581506dbb5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RAFO TECHNOLOGY INC" and pe.signatures[i].serial=="21:1b:5d:fe:65:bc:6f:34:bc:9d:3a:54" and 1526717931<=pe.signatures[i].not_after)
}
