import "pe"

rule REVERSINGLABS_Cert_Blocklist_085B70224253486624Fc36Fa658A1E32 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7d27604e-4ecd-559c-9180-4914e7f1f6c9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6846-L6862"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "50ff48a421a109f8c6bf92032691d9b673945bc591005004ff17dc18c97d4aea"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Best Fud, OOO" and pe.signatures[i].serial=="08:5b:70:22:42:53:48:66:24:fc:36:fa:65:8a:1e:32" and 1597971601<=pe.signatures[i].not_after)
}
