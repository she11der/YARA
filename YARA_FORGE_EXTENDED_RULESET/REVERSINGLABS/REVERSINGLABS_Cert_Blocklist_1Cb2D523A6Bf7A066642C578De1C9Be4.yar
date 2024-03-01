import "pe"

rule REVERSINGLABS_Cert_Blocklist_1Cb2D523A6Bf7A066642C578De1C9Be4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d2c87c29-cb64-5d43-847b-64c888421c1f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2376-L2392"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5a786b9ade5a59b8a1e0bbef1eb3dcb65404dcee19d572dc60f9ec9f45e4755b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shenzhen Hua\\xE2\\x80\\x99nan Xingfa Electronic Equipment Firm" and pe.signatures[i].serial=="1c:b2:d5:23:a6:bf:7a:06:66:42:c5:78:de:1c:9b:e4" and 1400889599<=pe.signatures[i].not_after)
}
