import "pe"

rule REVERSINGLABS_Cert_Blocklist_29128A56E7B3Bfb230742591Ac8B4718 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b868d2f2-3852-57a3-be01-32cc16eb2ff7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4106-L4122"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5a89fec015e56ddddaed75be91a87288dcd27841937d26e3416187913c4f0b85"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Programavimo paslaugos, MB" and pe.signatures[i].serial=="29:12:8a:56:e7:b3:bf:b2:30:74:25:91:ac:8b:47:18" and 1590900909<=pe.signatures[i].not_after)
}
