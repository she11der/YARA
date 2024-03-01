import "pe"

rule REVERSINGLABS_Cert_Blocklist_4152169F22454Ed604D03555B7Afb175 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e8975a1a-ac7c-5016-a206-de9ca7eea37f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4592-L4608"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fbb2124b934c270739f564317526d5b23b996364372426485d7c994a83293866"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SMACKTECH SOFTWARE LIMITED" and pe.signatures[i].serial=="41:52:16:9f:22:45:4e:d6:04:d0:35:55:b7:af:b1:75" and 1595808000<=pe.signatures[i].not_after)
}
