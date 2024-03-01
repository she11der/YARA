import "pe"

rule REVERSINGLABS_Cert_Blocklist_D627F1000D12485995514Bfbdefc55D9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4696fc12-16b7-575f-b90f-aa0a5cc12852"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5654-L5672"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7ca590d71997879d17054a936238dd5273a52f3438d1b231a75927abfb118ffd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THREE D CORPORATION PTY LTD" and (pe.signatures[i].serial=="00:d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9" or pe.signatures[i].serial=="d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9") and 1597622400<=pe.signatures[i].not_after)
}
