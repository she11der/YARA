import "pe"

rule REVERSINGLABS_Cert_Blocklist_2924785Fd7990B2D510675176Dae2Bed : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6898e95c-ee31-57a3-b764-99bf9008d0fe"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4724-L4740"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e308ca5f24ed5811e947289caf9aa820a16b08ea183c7aa9826f8a726fb5c3cf"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Neoopt LLC" and pe.signatures[i].serial=="29:24:78:5f:d7:99:0b:2d:51:06:75:17:6d:ae:2b:ed" and 1595000258<=pe.signatures[i].not_after)
}
