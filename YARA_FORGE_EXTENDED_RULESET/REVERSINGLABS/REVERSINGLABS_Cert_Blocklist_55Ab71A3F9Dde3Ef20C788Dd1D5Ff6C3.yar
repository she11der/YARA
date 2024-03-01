import "pe"

rule REVERSINGLABS_Cert_Blocklist_55Ab71A3F9Dde3Ef20C788Dd1D5Ff6C3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c8b5b632-26e6-5a78-99be-b50b1240dbec"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15554-L15570"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4bee740eaf359462cd85c6232160c6b1fc3df67acfe731da9978f0b8a304a93f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Zhengzhoushi Tiekelian Information Technology Co.,Ltd" and pe.signatures[i].serial=="55:ab:71:a3:f9:dd:e3:ef:20:c7:88:dd:1d:5f:f6:c3" and 1323907200<=pe.signatures[i].not_after)
}
