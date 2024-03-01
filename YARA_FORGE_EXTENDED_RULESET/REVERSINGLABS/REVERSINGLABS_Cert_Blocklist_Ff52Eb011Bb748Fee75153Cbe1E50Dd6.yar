import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ff52Eb011Bb748Fee75153Cbe1E50Dd6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "acd29c6d-27ed-587a-b17c-989e69082434"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11764-L11782"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8c80ed4e4f77df34ff9fcc712deda4c1bbedc588f2b01d02aa705e368fb98c5e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TASK ANNA LIMITED" and (pe.signatures[i].serial=="00:ff:52:eb:01:1b:b7:48:fe:e7:51:53:cb:e1:e5:0d:d6" or pe.signatures[i].serial=="ff:52:eb:01:1b:b7:48:fe:e7:51:53:cb:e1:e5:0d:d6") and 1647388800<=pe.signatures[i].not_after)
}
