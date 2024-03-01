import "pe"

rule REVERSINGLABS_Cert_Blocklist_253Ad25E39Abe8F8Fda9Fcf6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f09ca101-dd40-54d8-9235-1faf1e774dd4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13800-L13816"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1d46ccaa136cd7be30ffbf0eb09eb6485c543ff4bdbe99fa7ea3846841cbd41b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DVERI FADO, TOV" and pe.signatures[i].serial=="25:3a:d2:5e:39:ab:e8:f8:fd:a9:fc:f6" and 1538662130<=pe.signatures[i].not_after)
}
