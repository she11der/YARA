import "pe"

rule REVERSINGLABS_Cert_Blocklist_6767Def972D6Ea702D8C8A53Af1832D3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c60497b4-5abe-52b0-aac9-88953ea6cdf1"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L513-L529"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "aa7f997449b4b8dcf488cfb7f45ee98ca540d39fb861f5b01ff4bb4aa1875b72"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Guangzhou typical corner Network Technology Co., Ltd." and pe.signatures[i].serial=="67:67:de:f9:72:d6:ea:70:2d:8c:8a:53:af:18:32:d3" and 1361750400<=pe.signatures[i].not_after)
}
