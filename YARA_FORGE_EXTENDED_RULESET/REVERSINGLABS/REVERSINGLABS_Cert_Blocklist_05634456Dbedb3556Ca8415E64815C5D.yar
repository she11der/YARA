import "pe"

rule REVERSINGLABS_Cert_Blocklist_05634456Dbedb3556Ca8415E64815C5D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c9a05c35-2aed-5944-aad7-65ae2c290c6c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10570-L10586"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f5941c74821c0cd76633393d0346a9de2c7bccc666dc20b34c5b4d733faefc8f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Walden Intertech Inc." and pe.signatures[i].serial=="05:63:44:56:db:ed:b3:55:6c:a8:41:5e:64:81:5c:5d" and 1648425600<=pe.signatures[i].not_after)
}
