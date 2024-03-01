import "pe"

rule REVERSINGLABS_Cert_Blocklist_140D2C515E8Ee9739Bb5F1B2637Dc478 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "69f3ee46-87d2-5630-ba7c-4ed2924cf650"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16284-L16300"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e6724fe80959592c8741621ce604518d3e964cee5941257a99dda78b9c8bbdac"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Guangzhou YuanLuo Technology Co.,Ltd" and pe.signatures[i].serial=="14:0d:2c:51:5e:8e:e9:73:9b:b5:f1:b2:63:7d:c4:78" and 1386806400<=pe.signatures[i].not_after)
}
