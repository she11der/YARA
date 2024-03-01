import "pe"

rule REVERSINGLABS_Cert_Blocklist_432Eefc0D4Dc0326Eb277A518Cc4310A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "eeccb477-0bf7-5b79-94df-710e6e0db78f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13040-L13056"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d5a0b7f19f66f18b5ef1c548276b675ead74fed6be94310c303bfad6c85f18be"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and pe.signatures[i].serial=="43:2e:ef:c0:d4:dc:03:26:eb:27:7a:51:8c:c4:31:0a" and 1466121600<=pe.signatures[i].not_after)
}
