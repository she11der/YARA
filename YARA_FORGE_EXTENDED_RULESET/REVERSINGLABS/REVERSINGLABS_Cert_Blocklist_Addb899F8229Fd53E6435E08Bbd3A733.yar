import "pe"

rule REVERSINGLABS_Cert_Blocklist_Addb899F8229Fd53E6435E08Bbd3A733 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1e5f0577-ba05-5e43-a817-c75f65547c3d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8842-L8860"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ecb8e31b8c56b92cef601618e0adc2f6d88999318805b92389693aa9e8050d18"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "U.K. STEEL EXPORTS LIMITED" and (pe.signatures[i].serial=="00:ad:db:89:9f:82:29:fd:53:e6:43:5e:08:bb:d3:a7:33" or pe.signatures[i].serial=="ad:db:89:9f:82:29:fd:53:e6:43:5e:08:bb:d3:a7:33") and 1616630400<=pe.signatures[i].not_after)
}
