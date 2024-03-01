import "pe"

rule REVERSINGLABS_Cert_Blocklist_75Cf729F8A740Bbdef183A1C4D86A02F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e96fdf57-3884-526e-a704-93e783c95241"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6444-L6460"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "691fadaa653ecd29e60f2db39b7c5154d7c85f388f72eccd0a4b5fe42eaee0dd"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Umbor LLC" and pe.signatures[i].serial=="75:cf:72:9f:8a:74:0b:bd:ef:18:3a:1c:4d:86:a0:2f" and 1604223894<=pe.signatures[i].not_after)
}
