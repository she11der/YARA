import "pe"

rule REVERSINGLABS_Cert_Blocklist_082023879112289Bf351D297Cc8Efcfc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "94a4e3d6-2d0a-5e5d-9ae8-574ef9be017e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4816-L4832"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "58bec160445765ce45a26bf9d96ba6cfe61eee31e0953009d40a7ec64920c677"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STA-R TOV" and pe.signatures[i].serial=="08:20:23:87:91:12:28:9b:f3:51:d2:97:cc:8e:fc:fc" and 1573430400<=pe.signatures[i].not_after)
}
