import "pe"

rule REVERSINGLABS_Cert_Blocklist_C04F8F1E00C69E96A51Bf14Aab1C6Ae0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6513160e-ece5-500b-8b0b-4b8a6e04c0af"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3414-L3432"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "c2b5ffa305b761b57dd91c0acea0d8f82bec6b7d3608be10a20ea63621f3f3e8"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CHAIKA, TOV" and (pe.signatures[i].serial=="00:c0:4f:8f:1e:00:c6:9e:96:a5:1b:f1:4a:ab:1c:6a:e0" or pe.signatures[i].serial=="c0:4f:8f:1e:00:c6:9e:96:a5:1b:f1:4a:ab:1c:6a:e0") and 1551398400<=pe.signatures[i].not_after)
}
