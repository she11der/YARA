import "pe"

rule REVERSINGLABS_Cert_Blocklist_A7E1Dc5352C3852C5523030F57F2425C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a2795796-2897-55ad-936c-456c3b93bf14"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8318-L8336"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "79c42c9a4eeeb69a62a16590e2b0b63818785509a40d543c7efe27ec6baaa19e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pushka LLC" and (pe.signatures[i].serial=="00:a7:e1:dc:53:52:c3:85:2c:55:23:03:0f:57:f2:42:5c" or pe.signatures[i].serial=="a7:e1:dc:53:52:c3:85:2c:55:23:03:0f:57:f2:42:5c") and 1611792000<=pe.signatures[i].not_after)
}
