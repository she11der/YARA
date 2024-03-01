import "pe"

rule REVERSINGLABS_Cert_Blocklist_391Ae38670Ab188A5De26E07 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "aca9ac98-1c3b-5231-b6e5-97e3b8fec6de"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16138-L16154"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f7ccfadab650ae3b6f950c9d1b35f86aa4a4e6c05479c014ab18881a405678f0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DVERI FADO, TOV" and pe.signatures[i].serial=="39:1a:e3:86:70:ab:18:8a:5d:e2:6e:07" and 1540832872<=pe.signatures[i].not_after)
}
