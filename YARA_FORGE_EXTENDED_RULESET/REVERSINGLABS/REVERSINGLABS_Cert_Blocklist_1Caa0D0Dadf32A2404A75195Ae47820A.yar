import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Caa0D0Dadf32A2404A75195Ae47820A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5c1f82a4-c64d-556c-8c7a-213582e7bd5a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16266-L16282"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ab71e485c0b541fae79d246d34b1f4fb146747c1c3fb723aa87a7a32378ff974"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LivePlex Corp" and pe.signatures[i].serial=="1c:aa:0d:0d:ad:f3:2a:24:04:a7:51:95:ae:47:82:0a" and 1324425600<=pe.signatures[i].not_after)
}
