import "pe"

rule REVERSINGLABS_Cert_Blocklist_447F449121B883211663B7B7E2Ead868 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a3ee3618-0e20-5d9c-a514-9020607bd1b0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16194-L16210"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f473a939d1a27cf53c09d0e4a3753a9444ae3674a55d5b0feafeef6b75dd487f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "3 AM CHP" and pe.signatures[i].serial=="44:7f:44:91:21:b8:83:21:16:63:b7:b7:e2:ea:d8:68" and 1443052800<=pe.signatures[i].not_after)
}
