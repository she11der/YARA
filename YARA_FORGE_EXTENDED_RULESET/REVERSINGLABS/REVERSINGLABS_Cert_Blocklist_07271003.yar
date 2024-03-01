import "pe"

rule REVERSINGLABS_Cert_Blocklist_07271003 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "7573c436-5bf9-5522-9952-e30dbbccd092"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L801-L817"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "14c201b4fdda5b3553732a173a3d6705129c54f2a50d26997d63a77be8504285"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DigiNotar Cyber CA" and pe.signatures[i].serial=="07:27:10:03" and 1308182400<=pe.signatures[i].not_after)
}
