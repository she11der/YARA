import "pe"

rule REVERSINGLABS_Cert_Blocklist_890570B6B0E2868A53Be3F8F904A88Ee : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "681d233c-d5a2-5f25-bdb9-125149a291c4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11066-L11084"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fb7af8ec09da2fecaaaed8c7770966f11ef8a44a131553a9d1412387db2fb7ea"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JESEN LESS d.o.o." and (pe.signatures[i].serial=="00:89:05:70:b6:b0:e2:86:8a:53:be:3f:8f:90:4a:88:ee" or pe.signatures[i].serial=="89:05:70:b6:b0:e2:86:8a:53:be:3f:8f:90:4a:88:ee") and 1636588800<=pe.signatures[i].not_after)
}
