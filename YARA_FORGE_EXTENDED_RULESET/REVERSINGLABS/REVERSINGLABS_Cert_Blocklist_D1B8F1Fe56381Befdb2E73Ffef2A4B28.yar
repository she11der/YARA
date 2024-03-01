import "pe"

rule REVERSINGLABS_Cert_Blocklist_D1B8F1Fe56381Befdb2E73Ffef2A4B28 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "226371ea-670f-52f2-8dfc-78b30a29a5cc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8472-L8490"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c118cb46914e7a6df8dd33dd14d5f9cf2692d98311503ec850cc66f02c20839e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sein\\xC3\\xA4joen Squash ja Bowling Oy" and (pe.signatures[i].serial=="00:d1:b8:f1:fe:56:38:1b:ef:db:2e:73:ff:ef:2a:4b:28" or pe.signatures[i].serial=="d1:b8:f1:fe:56:38:1b:ef:db:2e:73:ff:ef:2a:4b:28") and 1617667200<=pe.signatures[i].not_after)
}
