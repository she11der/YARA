import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Cb6519B2528D006D1Da987153Dad2B3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "774e28f7-46ba-533d-a73c-00d2536c7d2b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15206-L15222"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "776402fc3a7de4843373bc1981f965fe9c2a9f1fe2374b142a96952fd05a591b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "D and D Internet Services" and pe.signatures[i].serial=="1c:b6:51:9b:25:28:d0:06:d1:da:98:71:53:da:d2:b3" and 1012780800<=pe.signatures[i].not_after)
}
