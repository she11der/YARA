import "pe"

rule REVERSINGLABS_Cert_Blocklist_3B0914E2982Be8980Aa23F49848555E5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "88ca65c4-ba0d-5676-979b-4fac737d4f21"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10144-L10160"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ea7d9fa7817751fef775765b54be5dd4d00c15ca50ac10fb40fb46cc3634c7b0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Office Rat s.r.o." and pe.signatures[i].serial=="3b:09:14:e2:98:2b:e8:98:0a:a2:3f:49:84:85:55:e5" and 1643155200<=pe.signatures[i].not_after)
}
