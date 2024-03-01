import "pe"

rule REVERSINGLABS_Cert_Blocklist_12D5A4B29Fe6156D4195Fba55Ae0D9A9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing GovRAT malware."
		author = "ReversingLabs"
		id = "45c37c98-1006-51e4-8832-b8e5c9fba416"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1544-L1560"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "860550745f6dbcd7dd0925d9b8f04e8e08e8b7c06343a4c070e131a815c42e12"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Open Source Developer, Marc Chapon" and pe.signatures[i].serial=="12:d5:a4:b2:9f:e6:15:6d:41:95:fb:a5:5a:e0:d9:a9" and 1404172799<=pe.signatures[i].not_after)
}
