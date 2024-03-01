import "pe"

rule REVERSINGLABS_Cert_Blocklist_6651Cc8B4850D4Dec61961503Ea7956B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "88679114-9c85-5810-af21-d5c2a8dc759e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13548-L13564"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "29bfe9c8b340b55a9daa2644e8d55b2b783cc95c85541732e6e0decca8c10ff6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NUSAAPPINSTALL(APPS INSTALLER S.L.)" and pe.signatures[i].serial=="66:51:cc:8b:48:50:d4:de:c6:19:61:50:3e:a7:95:6b" and 1436175828<=pe.signatures[i].not_after)
}
