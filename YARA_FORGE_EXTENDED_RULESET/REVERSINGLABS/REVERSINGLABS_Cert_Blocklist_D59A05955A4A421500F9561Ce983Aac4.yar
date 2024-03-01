import "pe"

rule REVERSINGLABS_Cert_Blocklist_D59A05955A4A421500F9561Ce983Aac4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "088f0f98-328b-50fa-b1e4-1d80023b3c09"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6216-L6234"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b7ed87a03f20872669369cc3cad4eae40ba597f06222194bd67262c094083ec1"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Olymp LLC" and (pe.signatures[i].serial=="00:d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4" or pe.signatures[i].serial=="d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4") and 1601895290<=pe.signatures[i].not_after)
}
