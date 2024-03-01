import "pe"

rule REVERSINGLABS_Cert_Blocklist_2C90Eaf4De3Afc03Ba924C719435C2A3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "06edc1a3-65b1-5a69-ab6b-4ffc3963513c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4870-L4888"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5bb78a5e39f9d023cf63edabdc83d4965fc79f6f04f9fea9bcf2a53223fbd4ca"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AntiFIX s.r.o." and (pe.signatures[i].serial=="00:2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3" or pe.signatures[i].serial=="2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3") and 1586293430<=pe.signatures[i].not_after)
}
