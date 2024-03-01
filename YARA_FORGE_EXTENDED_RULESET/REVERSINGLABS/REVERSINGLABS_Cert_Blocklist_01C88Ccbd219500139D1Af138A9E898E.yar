import "pe"

rule REVERSINGLABS_Cert_Blocklist_01C88Ccbd219500139D1Af138A9E898E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e3bd6be6-461c-56fd-8dfd-8205845f731e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4610-L4626"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d1acb0a7d6e20158797e77c066be42548cee9293fa94f24f936a95977ac16d91"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Raymond Yanagita" and pe.signatures[i].serial=="01:c8:8c:cb:d2:19:50:01:39:d1:af:13:8a:9e:89:8e" and 1593041280<=pe.signatures[i].not_after)
}
