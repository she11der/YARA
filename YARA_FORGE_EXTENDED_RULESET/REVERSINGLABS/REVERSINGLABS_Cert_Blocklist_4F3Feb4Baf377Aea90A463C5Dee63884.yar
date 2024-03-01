import "pe"

rule REVERSINGLABS_Cert_Blocklist_4F3Feb4Baf377Aea90A463C5Dee63884 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8de9bcf3-d705-590f-8898-52218f937571"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2934-L2950"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "56c37e758db33aa40e9a2c1c5a4eb14c2c370f614e838d86bf20c64f79e2a746"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "F3D LIMITED" and pe.signatures[i].serial=="4f:3f:eb:4b:af:37:7a:ea:90:a4:63:c5:de:e6:38:84" and 1526601599<=pe.signatures[i].not_after)
}
