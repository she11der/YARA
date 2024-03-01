import "pe"

rule REVERSINGLABS_Cert_Blocklist_32665079C5A5854A6833623Ca77Ff5Ac : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7078e95f-8bbe-5446-b9cb-c079f8448cb1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L387-L403"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6b734ca733c5fbadcb490ffd4c19c951e0fc17dd9b660eca948b126038c42cdb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ohanae" and pe.signatures[i].serial=="32:66:50:79:c5:a5:85:4a:68:33:62:3c:a7:7f:f5:ac" and 1381967999<=pe.signatures[i].not_after)
}
