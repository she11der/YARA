import "pe"

rule REVERSINGLABS_Cert_Blocklist_73Ecfdbb99Aec176Ddfcf7958D120E1A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "84e20878-e4ea-53a5-9c1b-04f3c66276de"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3452-L3468"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d911156707cef97acf79c096b5d4a4db166ddf05237168f1ecffb0c0a2ebd8fa"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MHOW PTY LTD" and pe.signatures[i].serial=="73:ec:fd:bb:99:ae:c1:76:dd:fc:f7:95:8d:12:0e:1a" and 1566864000<=pe.signatures[i].not_after)
}
