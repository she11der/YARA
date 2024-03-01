import "pe"

rule REVERSINGLABS_Cert_Blocklist_6E44Fcedd49F22F7A28Cecc99104F61A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "b69a4e06-a732-5462-b2b1-bdde3fd34e31"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12500-L12516"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "caff0cbca45c0dffb673367585824783371f2f4e31a0c9629afb7de708098892"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "M-Trans Maciej Caban" and pe.signatures[i].serial=="6e:44:fc:ed:d4:9f:22:f7:a2:8c:ec:c9:91:04:f6:1a" and 1672923378<=pe.signatures[i].not_after)
}
