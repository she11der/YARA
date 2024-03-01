import "pe"

rule REVERSINGLABS_Cert_Blocklist_9C4816D900A6Ecdbe54Adf72B19Ebcf5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bd22372d-774b-5e25-b4e5-47d34fe1c40b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3846-L3864"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "92e8130f444417d5bc3788721280338bbed33e3362104de0cf27bc7c1fc30d0e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Datamingo Limited" and (pe.signatures[i].serial=="00:9c:48:16:d9:00:a6:ec:db:e5:4a:df:72:b1:9e:bc:f5" or pe.signatures[i].serial=="9c:48:16:d9:00:a6:ec:db:e5:4a:df:72:b1:9e:bc:f5") and 1557187200<=pe.signatures[i].not_after)
}
