import "pe"

rule REVERSINGLABS_Cert_Blocklist_77A64759F12766E363D779998C71Bdc9 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "98acd01b-c452-530d-8814-2591810ecd53"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2320-L2336"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2bf3d99ddec6b76da1ca60a9285767a5b34b84455db58195fc5d8fd8a22c9f8a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing Gigabit Times Technology Co., Ltd" and pe.signatures[i].serial=="77:a6:47:59:f1:27:66:e3:63:d7:79:99:8c:71:bd:c9" and 1301011199<=pe.signatures[i].not_after)
}
