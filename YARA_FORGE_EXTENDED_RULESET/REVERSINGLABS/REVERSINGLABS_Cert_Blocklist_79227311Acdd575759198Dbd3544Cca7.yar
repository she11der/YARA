import "pe"

rule REVERSINGLABS_Cert_Blocklist_79227311Acdd575759198Dbd3544Cca7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "350f7c25-f20f-5e8f-aa52-163cf3de3be1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15792-L15808"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "73e920d51faf7150329ce189d1693c29a2285a02d54fee27e5af5afe3238295b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xin Zhou" and pe.signatures[i].serial=="79:22:73:11:ac:dd:57:57:59:19:8d:bd:35:44:cc:a7" and 1478131200<=pe.signatures[i].not_after)
}
