import "pe"

rule REVERSINGLABS_Cert_Blocklist_B191812516E6618D49E6Ccf5E63Dc343 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "8f316011-9a29-5366-a26a-1fe20651ef17"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1308-L1324"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "40c03e683b4b8e8a23ca84da7dfd3bd998d3708b27b7df7a22f25fb364c3a69b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Adobe Systems" and pe.signatures[i].serial=="b1:91:81:25:16:e6:61:8d:49:e6:cc:f5:e6:3d:c3:43" and 1341792000<=pe.signatures[i].not_after)
}
