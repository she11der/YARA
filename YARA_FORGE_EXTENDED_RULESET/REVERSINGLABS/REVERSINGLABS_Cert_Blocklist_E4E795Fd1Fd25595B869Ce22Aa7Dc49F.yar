import "pe"

rule REVERSINGLABS_Cert_Blocklist_E4E795Fd1Fd25595B869Ce22Aa7Dc49F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9c6d2be7-093c-5ce2-83af-6ab9b46603bc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11880-L11898"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ced47bd69b58de9e6b2aa7518ccceca088884acb79c0803c3defe6b115a0abb6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OASIS COURT LIMITED" and (pe.signatures[i].serial=="00:e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f" or pe.signatures[i].serial=="e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f") and 1608508800<=pe.signatures[i].not_after)
}
