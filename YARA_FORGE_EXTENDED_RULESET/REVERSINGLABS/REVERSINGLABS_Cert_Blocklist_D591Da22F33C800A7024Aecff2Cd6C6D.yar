import "pe"

rule REVERSINGLABS_Cert_Blocklist_D591Da22F33C800A7024Aecff2Cd6C6D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "294cbf90-cd1f-5743-a51a-46e1d04ef34e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5540-L5558"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "30e421d5ea3c5693c5c9bd0e3dd997ceda9755d17e3fb16d2a8e6c4a327ae32f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO T2 Soft" and (pe.signatures[i].serial=="00:d5:91:da:22:f3:3c:80:0a:70:24:ae:cf:f2:cd:6c:6d" or pe.signatures[i].serial=="d5:91:da:22:f3:3c:80:0a:70:24:ae:cf:f2:cd:6c:6d") and 1588679107<=pe.signatures[i].not_after)
}
