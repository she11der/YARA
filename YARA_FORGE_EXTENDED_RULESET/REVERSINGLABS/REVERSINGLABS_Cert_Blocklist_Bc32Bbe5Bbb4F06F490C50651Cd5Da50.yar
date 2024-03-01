import "pe"

rule REVERSINGLABS_Cert_Blocklist_Bc32Bbe5Bbb4F06F490C50651Cd5Da50 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "eb6ccc6d-2a66-5113-8b78-c32012431123"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2842-L2860"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "104be481b7d4b1cb3c43c72314afc3641983838b5177c34a88d6da0d0e7b89c9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Remedica Medical Education and Publishing Ltd" and (pe.signatures[i].serial=="00:bc:32:bb:e5:bb:b4:f0:6f:49:0c:50:65:1c:d5:da:50" or pe.signatures[i].serial=="bc:32:bb:e5:bb:b4:f0:6f:49:0c:50:65:1c:d5:da:50") and 1387151999<=pe.signatures[i].not_after)
}
