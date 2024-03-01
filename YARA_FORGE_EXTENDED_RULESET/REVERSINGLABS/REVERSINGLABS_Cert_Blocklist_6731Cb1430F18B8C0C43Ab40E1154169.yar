import "pe"

rule REVERSINGLABS_Cert_Blocklist_6731Cb1430F18B8C0C43Ab40E1154169 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "df2423da-37ec-5adc-8497-2ac975b0b7ff"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16818-L16834"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c05349166919ffc18ac6ecb61b822a8365f87a82164c5e110ef94345bdc4de6f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "3 AM CHP" and pe.signatures[i].serial=="67:31:cb:14:30:f1:8b:8c:0c:43:ab:40:e1:15:41:69" and 1436313600<=pe.signatures[i].not_after)
}
