import "pe"

rule REVERSINGLABS_Cert_Blocklist_82D224323Efa65060B641F51Fadfef02 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "166949cf-dbff-5713-950e-46d1f3edc61f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11046-L11064"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9d361c91ed24b6c20a7b35957e26f208ce8e0a3d79c5a6fed6278acd826ccf49"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAVAS INVESTMENTS PTY LTD" and (pe.signatures[i].serial=="00:82:d2:24:32:3e:fa:65:06:0b:64:1f:51:fa:df:ef:02" or pe.signatures[i].serial=="82:d2:24:32:3e:fa:65:06:0b:64:1f:51:fa:df:ef:02") and 1665100800<=pe.signatures[i].not_after)
}
