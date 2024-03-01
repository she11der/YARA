import "pe"

rule REVERSINGLABS_Cert_Blocklist_7D36Cbb64Bc9Add17Ba71737D3Ecceca : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ce10840c-150d-5ecd-ab9a-7bc96092ebfd"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6938-L6954"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5874860582ed5be6908dca38e6ecae831eeeb0c2b768e8065ada9fd5ac2bda89"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LTD SERVICES LIMITED" and pe.signatures[i].serial=="7d:36:cb:b6:4b:c9:ad:d1:7b:a7:17:37:d3:ec:ce:ca" and 1616025600<=pe.signatures[i].not_after)
}
