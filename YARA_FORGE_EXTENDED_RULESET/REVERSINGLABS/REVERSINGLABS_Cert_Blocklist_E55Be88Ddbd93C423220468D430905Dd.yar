import "pe"

rule REVERSINGLABS_Cert_Blocklist_E55Be88Ddbd93C423220468D430905Dd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "37e60515-0395-51a5-8bfa-35e3e336d60c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10050-L10068"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "05b2f297454e7080591b85991b224193eb89fc5074eb3c2e484ceadad2de4cb7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VALVE ACTUATION LTD" and (pe.signatures[i].serial=="00:e5:5b:e8:8d:db:d9:3c:42:32:20:46:8d:43:09:05:dd" or pe.signatures[i].serial=="e5:5b:e8:8d:db:d9:3c:42:32:20:46:8d:43:09:05:dd") and 1637712000<=pe.signatures[i].not_after)
}
