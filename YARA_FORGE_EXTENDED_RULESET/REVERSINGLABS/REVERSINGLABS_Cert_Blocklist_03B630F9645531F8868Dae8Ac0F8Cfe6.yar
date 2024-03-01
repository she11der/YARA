import "pe"

rule REVERSINGLABS_Cert_Blocklist_03B630F9645531F8868Dae8Ac0F8Cfe6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "be945687-9b8c-5d84-9992-fd317eddae54"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4968-L4984"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6d2f4346760bf52a438c4c996e92a2641bebfd536248776383d7c8394e094e6a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Geksan LLC" and pe.signatures[i].serial=="03:b6:30:f9:64:55:31:f8:86:8d:ae:8a:c0:f8:cf:e6" and 1594252801<=pe.signatures[i].not_after)
}
