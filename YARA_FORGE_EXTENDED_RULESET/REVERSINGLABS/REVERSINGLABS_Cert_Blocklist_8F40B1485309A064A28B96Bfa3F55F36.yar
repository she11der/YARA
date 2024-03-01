import "pe"

rule REVERSINGLABS_Cert_Blocklist_8F40B1485309A064A28B96Bfa3F55F36 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bad5b57e-185a-5872-9817-a7d688e24fe7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3194-L3212"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "58dd47bfd2acd698bc27fb03eb51e4b8598ef6c71f7193e3cc4eea63982855f0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Singh Agile Content Design Limited" and (pe.signatures[i].serial=="00:8f:40:b1:48:53:09:a0:64:a2:8b:96:bf:a3:f5:5f:36" or pe.signatures[i].serial=="8f:40:b1:48:53:09:a0:64:a2:8b:96:bf:a3:f5:5f:36") and 1542585600<=pe.signatures[i].not_after)
}
