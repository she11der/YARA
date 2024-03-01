import "pe"

rule REVERSINGLABS_Cert_Blocklist_50D08F3C9Bf86Fba52Cf592B4Fe6Eacf : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f315cdda-4b95-534d-94db-9a04e2da6385"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14932-L14948"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ca613e4b45b9bb1ef7564b9fc6321bccc0f683298de692a3db2bf841db9010ef"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CLEVERCYBER LTD" and pe.signatures[i].serial=="50:d0:8f:3c:9b:f8:6f:ba:52:cf:59:2b:4f:e6:ea:cf" and 1518134400<=pe.signatures[i].not_after)
}
