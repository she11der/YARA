import "pe"

rule REVERSINGLABS_Cert_Blocklist_61Fe6F00Bd79684210534050Ff46Bc92 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b88e0bbf-ab3a-51ac-8542-d4f92116f5e9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14242-L14258"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e8ebc5de081e2d1e653493a2d85699ebfb5227b7fab656468025c2043903f597"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Xingning Dexin Network Technology Co., Ltd." and pe.signatures[i].serial=="61:fe:6f:00:bd:79:68:42:10:53:40:50:ff:46:bc:92" and 1512000000<=pe.signatures[i].not_after)
}
