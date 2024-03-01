import "pe"

rule REVERSINGLABS_Cert_Blocklist_74702Dff5D4056B847D009A2265Fb1B3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "55f1e321-ce70-519a-9a39-4278162edbef"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15954-L15970"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8acc57bbf334a48043dbee6fab7b7a54a44801b2ccd0ccd9d14194689c75c021"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shulan Hou" and pe.signatures[i].serial=="74:70:2d:ff:5d:40:56:b8:47:d0:09:a2:26:5f:b1:b3" and 1469664000<=pe.signatures[i].not_after)
}
