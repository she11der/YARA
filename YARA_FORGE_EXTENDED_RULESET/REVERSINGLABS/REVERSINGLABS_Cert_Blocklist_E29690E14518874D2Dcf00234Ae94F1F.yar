import "pe"

rule REVERSINGLABS_Cert_Blocklist_E29690E14518874D2Dcf00234Ae94F1F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6b4f26d3-b943-5a2e-bfb9-0e290031926a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5250-L5268"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ef84815798b213dc49a142e3076cc6dd680dccabe72643fc86234024a46468f9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GRIND & TAMP ENTERPRISES PTY LTD" and (pe.signatures[i].serial=="00:e2:96:90:e1:45:18:87:4d:2d:cf:00:23:4a:e9:4f:1f" or pe.signatures[i].serial=="e2:96:90:e1:45:18:87:4d:2d:cf:00:23:4a:e9:4f:1f") and 1570838400<=pe.signatures[i].not_after)
}
