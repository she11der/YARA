import "pe"

rule REVERSINGLABS_Cert_Blocklist_470D6Ce21A6940320261F09E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "00b92b5d-59e3-5aae-954d-a90bd8cc1370"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13058-L13074"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "cae1d381bf2018a0ce56feb245d01f2bfea55b67894264d32d78dbb41873c792"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="47:0d:6c:e2:1a:69:40:32:02:61:f0:9e" and 1474523038<=pe.signatures[i].not_after)
}
