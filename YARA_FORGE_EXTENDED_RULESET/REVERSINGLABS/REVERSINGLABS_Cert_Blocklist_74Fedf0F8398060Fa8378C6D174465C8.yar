import "pe"

rule REVERSINGLABS_Cert_Blocklist_74Fedf0F8398060Fa8378C6D174465C8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "eea46214-d0f5-5e92-b678-4a1df09025ce"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3378-L3394"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "406821c7990f05fdad91704f6418304f53dd4800bc4b41912177a1695858fade"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DOCS PTY LTD" and pe.signatures[i].serial=="74:fe:df:0f:83:98:06:0f:a8:37:8c:6d:17:44:65:c8" and 1566172800<=pe.signatures[i].not_after)
}
