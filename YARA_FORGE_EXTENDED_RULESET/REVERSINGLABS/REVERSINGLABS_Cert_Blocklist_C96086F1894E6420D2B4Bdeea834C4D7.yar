import "pe"

rule REVERSINGLABS_Cert_Blocklist_C96086F1894E6420D2B4Bdeea834C4D7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1268461b-676c-59b8-80c1-c54dbe1a265f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10276-L10294"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "949bbd41ad4c83a05c1f004786cd296e2af80a3a559955ec90a4675cdfa04258"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE FAITH SP Z O O" and (pe.signatures[i].serial=="00:c9:60:86:f1:89:4e:64:20:d2:b4:bd:ee:a8:34:c4:d7" or pe.signatures[i].serial=="c9:60:86:f1:89:4e:64:20:d2:b4:bd:ee:a8:34:c4:d7") and 1644969600<=pe.signatures[i].not_after)
}
