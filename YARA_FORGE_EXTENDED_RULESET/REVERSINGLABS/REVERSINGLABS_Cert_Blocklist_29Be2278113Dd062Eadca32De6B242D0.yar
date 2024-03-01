import "pe"

rule REVERSINGLABS_Cert_Blocklist_29Be2278113Dd062Eadca32De6B242D0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a2dfd6e0-4475-537a-859e-126dd4a02af7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15900-L15916"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3df7afba9eda9022a64647ce2a91119d0bdf6fe5b164a1e82b1819409024fbee"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BLADES" and pe.signatures[i].serial=="29:be:22:78:11:3d:d0:62:ea:dc:a3:2d:e6:b2:42:d0" and 1536883200<=pe.signatures[i].not_after)
}
