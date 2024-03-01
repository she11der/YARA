import "pe"

rule REVERSINGLABS_Cert_Blocklist_0F20A5155E53Ce20Bb644F646Ed6A2Fd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d52066d5-9bc1-5f72-8e97-7efda88c14b2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9842-L9858"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "70d57f2c24d4ae6f17339bfb998589a3b10f5dd4b19ac8a5bc99e082145c4ed0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CB CAM SP Z O O" and pe.signatures[i].serial=="0f:20:a5:15:5e:53:ce:20:bb:64:4f:64:6e:d6:a2:fd" and 1635196200<=pe.signatures[i].not_after)
}
