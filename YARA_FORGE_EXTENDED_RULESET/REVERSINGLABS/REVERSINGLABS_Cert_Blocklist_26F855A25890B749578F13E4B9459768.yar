import "pe"

rule REVERSINGLABS_Cert_Blocklist_26F855A25890B749578F13E4B9459768 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d873b0d4-dff5-5ee2-a70f-b067602b217e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10698-L10714"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "35bfa39ef8f03d10af884f288278ea6ad3aff31cbae111057c2b619c6dc0a752"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Boo\\xE2\\x80\\x99s Q & Sweets Corporation" and pe.signatures[i].serial=="26:f8:55:a2:58:90:b7:49:57:8f:13:e4:b9:45:97:68" and 1645401600<=pe.signatures[i].not_after)
}
