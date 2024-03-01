import "pe"

rule REVERSINGLABS_Cert_Blocklist_6314001C3235Cd59Bcc3F5278C518804 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "aff0fb76-587b-5493-810c-ac32a6ba9576"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5902-L5918"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4320f3884c0f7e4939e8988a4e83b8028a5e01fb425ae4faa2273134db835813"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GIE-MUTUALISTE" and pe.signatures[i].serial=="63:14:00:1c:32:35:cd:59:bc:c3:f5:27:8c:51:88:04" and 1600304400<=pe.signatures[i].not_after)
}
