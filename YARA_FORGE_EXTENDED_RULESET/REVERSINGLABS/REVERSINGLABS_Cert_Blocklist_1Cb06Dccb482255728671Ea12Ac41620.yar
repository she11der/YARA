import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Cb06Dccb482255728671Ea12Ac41620 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "5a7f61a4-15ba-5f5c-89e1-b8b986e13f19"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1798-L1814"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e0867ffe2ddd28282fe78b27b3b12ebac525b33a27dd242bc6f55bcd2e066a18"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fangzhen Li" and pe.signatures[i].serial=="1c:b0:6d:cc:b4:82:25:57:28:67:1e:a1:2a:c4:16:20" and 1445126399<=pe.signatures[i].not_after)
}
