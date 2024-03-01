import "pe"

rule REVERSINGLABS_Cert_Blocklist_098A57 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4604f1a6-2fdb-5917-943d-f0e2dbaaa29e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14112-L14128"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5e203f87dd4608ba5d583e02ce86fbe230e45fff86a7a697766e149d0cf6f436"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ELECTRONIC GROUP" and pe.signatures[i].serial=="09:8a:57" and 1032855179<=pe.signatures[i].not_after)
}
