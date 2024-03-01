import "pe"

rule REVERSINGLABS_Cert_Blocklist_3E72Daf2B9A4449E946009E5084A8E76 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "aa7c6cbe-0794-59e3-a675-93beeccc9784"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4032-L4048"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f1a7bf6c18e0ebf8aef53feb7d7789ce87c96e00962c64e07a37d968702d2fa5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Infoteh63" and pe.signatures[i].serial=="3e:72:da:f2:b9:a4:44:9e:94:60:09:e5:08:4a:8e:76" and 1591787570<=pe.signatures[i].not_after)
}
