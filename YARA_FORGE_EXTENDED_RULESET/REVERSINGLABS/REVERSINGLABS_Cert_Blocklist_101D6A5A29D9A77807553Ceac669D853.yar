import "pe"

rule REVERSINGLABS_Cert_Blocklist_101D6A5A29D9A77807553Ceac669D853 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "918fa696-5c92-551b-a87b-6410a6dc718a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10480-L10496"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bce92750f71477ecfa7b8213724344708066c0e6133a47cd6758bbd9f8f9da5f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BIC GROUP LIMITED" and pe.signatures[i].serial=="10:1d:6a:5a:29:d9:a7:78:07:55:3c:ea:c6:69:d8:53" and 1646352000<=pe.signatures[i].not_after)
}
