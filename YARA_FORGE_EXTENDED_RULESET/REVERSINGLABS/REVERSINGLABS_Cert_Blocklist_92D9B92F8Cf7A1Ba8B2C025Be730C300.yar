import "pe"

rule REVERSINGLABS_Cert_Blocklist_92D9B92F8Cf7A1Ba8B2C025Be730C300 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bc37efaa-9ceb-5079-999f-b3d17c585b1c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11122-L11140"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2a0be6157e589705ad19756971bd865edad2d54760d03c2e6f47a461b402ad68"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "UPLagga Systems s.r.o." and (pe.signatures[i].serial=="00:92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00" or pe.signatures[i].serial=="92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00") and 1598054400<=pe.signatures[i].not_after)
}
