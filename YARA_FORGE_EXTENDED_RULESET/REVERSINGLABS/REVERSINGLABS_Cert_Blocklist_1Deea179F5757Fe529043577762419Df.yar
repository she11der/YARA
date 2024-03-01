import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Deea179F5757Fe529043577762419Df : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ef29c813-e914-5766-990f-76c14d18ec79"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10734-L10750"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "67c3d3496caf54ca0b1afc4d1dcc902e2f3632ac6708f85e163d427b567d098f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPIRIT CONSULTING s. r. o." and pe.signatures[i].serial=="1d:ee:a1:79:f5:75:7f:e5:29:04:35:77:76:24:19:df" and 1645401600<=pe.signatures[i].not_after)
}
