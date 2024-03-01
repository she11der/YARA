import "pe"

rule REVERSINGLABS_Cert_Blocklist_4A7F07C5D4Ad2E23F9E8E03F0E229Dd4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "76be58d9-d1a3-5dec-807e-941714be80f9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12572-L12588"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6dc2bfac77117e294cacc772f7bfaea8b2e3caa26a0afd3729d517e91ca20ea5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Danalis LLC" and pe.signatures[i].serial=="4a:7f:07:c5:d4:ad:2e:23:f9:e8:e0:3f:0e:22:9d:d4" and 1608681600<=pe.signatures[i].not_after)
}
