import "pe"

rule REVERSINGLABS_Cert_Blocklist_F2D693Aad63E6920782A0027Dfc97D91 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c4876bdd-35bc-5a3f-9f55-9a730e7ff5c8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7142-L7160"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8f29e65b39608518d16f708faef68db37b6e179c567819dccb6681adcec262e3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EKO-KHIM TOV" and (pe.signatures[i].serial=="00:f2:d6:93:aa:d6:3e:69:20:78:2a:00:27:df:c9:7d:91" or pe.signatures[i].serial=="f2:d6:93:aa:d6:3e:69:20:78:2a:00:27:df:c9:7d:91") and 1598989763<=pe.signatures[i].not_after)
}
