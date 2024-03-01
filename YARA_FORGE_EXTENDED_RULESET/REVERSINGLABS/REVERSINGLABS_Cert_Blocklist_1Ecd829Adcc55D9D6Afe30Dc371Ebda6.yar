import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Ecd829Adcc55D9D6Afe30Dc371Ebda6 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "db9f022b-f650-5d40-ae84-4df92b0f3a96"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4402-L4420"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "02955f4df7deccab52cdd82fd04d5012db7440f85c87d750fa9f81ff85e2dab0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Komp.IT" and (pe.signatures[i].serial=="00:1e:cd:82:9a:dc:c5:5d:9d:6a:fe:30:dc:37:1e:bd:a6" or pe.signatures[i].serial=="1e:cd:82:9a:dc:c5:5d:9d:6a:fe:30:dc:37:1e:bd:a6") and 1588723200<=pe.signatures[i].not_after)
}
