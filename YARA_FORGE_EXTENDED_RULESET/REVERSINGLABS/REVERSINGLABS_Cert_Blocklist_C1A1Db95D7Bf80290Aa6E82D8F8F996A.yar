import "pe"

rule REVERSINGLABS_Cert_Blocklist_C1A1Db95D7Bf80290Aa6E82D8F8F996A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c04a2731-5eb8-5db4-9e88-cab9b61952e4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8862-L8880"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "84c7c0e53facadcdfd752e9cf3811fbfd6aac4bef4109acf430a67b6dcd37bfc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Software Two Pty Ltd" and (pe.signatures[i].serial=="00:c1:a1:db:95:d7:bf:80:29:0a:a6:e8:2d:8f:8f:99:6a" or pe.signatures[i].serial=="c1:a1:db:95:d7:bf:80:29:0a:a6:e8:2d:8f:8f:99:6a") and 1615334400<=pe.signatures[i].not_after)
}
