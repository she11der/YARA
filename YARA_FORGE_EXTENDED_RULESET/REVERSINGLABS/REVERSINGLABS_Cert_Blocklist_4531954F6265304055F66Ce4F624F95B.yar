import "pe"

rule REVERSINGLABS_Cert_Blocklist_4531954F6265304055F66Ce4F624F95B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "da1aaa4c-ac71-5c4c-b663-3d1b57d69040"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L117-L133"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "58d3a2a5e3f6730f329bddb171ad6332794fa95848825b892c3b8324f503ae89"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IDAutomation.com" and pe.signatures[i].serial=="45:31:95:4f:62:65:30:40:55:f6:6c:e4:f6:24:f9:5b" and 1384819199<=pe.signatures[i].not_after)
}
