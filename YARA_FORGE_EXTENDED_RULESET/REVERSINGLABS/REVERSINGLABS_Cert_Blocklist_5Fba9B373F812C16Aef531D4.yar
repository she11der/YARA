import "pe"

rule REVERSINGLABS_Cert_Blocklist_5Fba9B373F812C16Aef531D4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "129e981a-064a-5930-bd45-d03ed008451c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15864-L15880"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8b7340359778e3aa56f6ea300973af74eb77efd54108d2ca2b6b8f04d89a1c39"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and pe.signatures[i].serial=="5f:ba:9b:37:3f:81:2c:16:ae:f5:31:d4" and 1473329076<=pe.signatures[i].not_after)
}
