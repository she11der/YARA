import "pe"

rule REVERSINGLABS_Cert_Blocklist_31D852F5Fca1A5966B5Ed08A14825C54 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "362a6eb7-f49e-502b-9870-522aea13e04b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7580-L7596"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "8c98b856d53e6862e94042bb133f5739bddcec2e208e43961b23e244584c6ee4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BBT KLA d.o.o." and pe.signatures[i].serial=="31:d8:52:f5:fc:a1:a5:96:6b:5e:d0:8a:14:82:5c:54" and 1612396800<=pe.signatures[i].not_after)
}
