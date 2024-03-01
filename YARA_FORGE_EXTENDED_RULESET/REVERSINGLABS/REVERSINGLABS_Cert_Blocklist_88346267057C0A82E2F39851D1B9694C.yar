import "pe"

rule REVERSINGLABS_Cert_Blocklist_88346267057C0A82E2F39851D1B9694C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "3be920eb-7b71-53c4-94b7-0ffc88d14c59"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L17160-L17178"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "60acdbad8ad3e1d4a863ce160d93abd0b5e2b214858cba84f7a1b907d2491486"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Hudson LLC" and (pe.signatures[i].serial=="00:88:34:62:67:05:7c:0a:82:e2:f3:98:51:d1:b9:69:4c" or pe.signatures[i].serial=="88:34:62:67:05:7c:0a:82:e2:f3:98:51:d1:b9:69:4c") and 1595376000<=pe.signatures[i].not_after)
}
