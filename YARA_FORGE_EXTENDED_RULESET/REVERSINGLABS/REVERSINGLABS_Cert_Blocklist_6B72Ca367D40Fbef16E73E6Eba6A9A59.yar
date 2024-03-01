import "pe"

rule REVERSINGLABS_Cert_Blocklist_6B72Ca367D40Fbef16E73E6Eba6A9A59 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e1cf9568-9a6a-58cb-81a4-25063ccc1ac7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13440-L13456"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2b20c16dafcd891c36b28b36093cd3ad3a15f3795f0f2adda61fb0db2835d02d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="6b:72:ca:36:7d:40:fb:ef:16:e7:3e:6e:ba:6a:9a:59" and 1476748800<=pe.signatures[i].not_after)
}
