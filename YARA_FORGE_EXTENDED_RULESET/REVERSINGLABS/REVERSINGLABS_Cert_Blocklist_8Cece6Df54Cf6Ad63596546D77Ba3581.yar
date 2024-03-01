import "pe"

rule REVERSINGLABS_Cert_Blocklist_8Cece6Df54Cf6Ad63596546D77Ba3581 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bde12eeb-c4f8-5da3-8493-0f94cb1bf1f7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11724-L11742"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d6b5bca36ef492ce9b79be905c86c66d43ef38701dafeed977229034119bd00d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Mikael LLC" and (pe.signatures[i].serial=="00:8c:ec:e6:df:54:cf:6a:d6:35:96:54:6d:77:ba:35:81" or pe.signatures[i].serial=="8c:ec:e6:df:54:cf:6a:d6:35:96:54:6d:77:ba:35:81") and 1613088000<=pe.signatures[i].not_after)
}
