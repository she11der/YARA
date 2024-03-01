import "pe"

rule REVERSINGLABS_Cert_Blocklist_338483Cc174C16Ebc454A3803Ffd4217 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ce30ace6-c2c2-5f3e-a2f7-1f08825d44eb"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9804-L9820"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7d7dd55eaab15cf458e5e57f0e5fbebdcc9313aee05394310a5cf9d9b4def153"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lpr:n Laatu-Ravintolat Oy" and pe.signatures[i].serial=="33:84:83:cc:17:4c:16:eb:c4:54:a3:80:3f:fd:42:17" and 1635208206<=pe.signatures[i].not_after)
}
