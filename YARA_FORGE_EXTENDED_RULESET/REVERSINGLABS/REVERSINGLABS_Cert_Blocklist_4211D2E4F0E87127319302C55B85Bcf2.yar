import "pe"

rule REVERSINGLABS_Cert_Blocklist_4211D2E4F0E87127319302C55B85Bcf2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dbe2a945-cf13-564a-a95a-24534c70a723"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L585-L601"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "edf9bbface7fe943dfa4f5a6e8469802ccdbd3de9d3e6b8fabebb024c21bb9a9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "yinsheng xie" and pe.signatures[i].serial=="42:11:d2:e4:f0:e8:71:27:31:93:02:c5:5b:85:bc:f2" and 1360713599<=pe.signatures[i].not_after)
}
