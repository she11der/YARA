import "pe"

rule REVERSINGLABS_Cert_Blocklist_2888Cf0F953A4A3640Ee4Cfc6304D9D4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "75ec52c5-4c59-51d8-bd9b-928c75d3521a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7864-L7880"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a9ee8534d89b8ac8705bb1777718513a28e4531ed398f482f46a72f2760af161"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lotte Schmidt" and pe.signatures[i].serial=="28:88:cf:0f:95:3a:4a:36:40:ee:4c:fc:63:04:d9:d4" and 1608024974<=pe.signatures[i].not_after)
}
