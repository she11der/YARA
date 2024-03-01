import "pe"

rule REVERSINGLABS_Cert_Blocklist_D79739187C585E453C00Afc11D77B523 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ed427336-6833-5e09-8ebe-039c8cd50846"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9494-L9512"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6d6db87227d7be559afa67c4f2b65b01f26741fdf337d920241a633bb036426f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAN MARINO INVESTMENTS PTY LTD" and (pe.signatures[i].serial=="00:d7:97:39:18:7c:58:5e:45:3c:00:af:c1:1d:77:b5:23" or pe.signatures[i].serial=="d7:97:39:18:7c:58:5e:45:3c:00:af:c1:1d:77:b5:23") and 1631059200<=pe.signatures[i].not_after)
}
