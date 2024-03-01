import "pe"

rule REVERSINGLABS_Cert_Blocklist_2C1Ee9B583310B5E34A1Ee6945A34B26 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "70fc063e-f032-5e63-ae53-65a25d5a29c3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8092-L8108"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "7752e49e8848863d78c5de03c3d194498765d80da00a84c5164c7a9010d13474"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Artmarket" and pe.signatures[i].serial=="2c:1e:e9:b5:83:31:0b:5e:34:a1:ee:69:45:a3:4b:26" and 1607558400<=pe.signatures[i].not_after)
}
