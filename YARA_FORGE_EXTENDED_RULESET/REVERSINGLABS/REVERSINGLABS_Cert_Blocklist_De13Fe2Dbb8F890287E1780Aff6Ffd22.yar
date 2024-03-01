import "pe"

rule REVERSINGLABS_Cert_Blocklist_De13Fe2Dbb8F890287E1780Aff6Ffd22 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d2b15920-76ae-54e4-988c-278a3622ec52"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3488-L3504"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ebd983bcfa1e5d54af9d9e07d80d05f4752040eab92e63cd986db789fa07026f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LAST TIME PTY LTD" and pe.signatures[i].serial=="de:13:fe:2d:bb:8f:89:02:87:e1:78:0a:ff:6f:fd:22" and 1566259200<=pe.signatures[i].not_after)
}
