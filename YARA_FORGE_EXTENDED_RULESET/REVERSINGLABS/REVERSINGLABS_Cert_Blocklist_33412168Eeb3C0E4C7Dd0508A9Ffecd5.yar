import "pe"

rule REVERSINGLABS_Cert_Blocklist_33412168Eeb3C0E4C7Dd0508A9Ffecd5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "db2ae33e-d3af-5200-ad15-824e29434e2c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16944-L16960"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d634af0637c3349fe1718ee807b8a75007ab46b141494331901a22ce54e9fc5d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and pe.signatures[i].serial=="33:41:21:68:ee:b3:c0:e4:c7:dd:05:08:a9:ff:ec:d5" and 1467590400<=pe.signatures[i].not_after)
}
