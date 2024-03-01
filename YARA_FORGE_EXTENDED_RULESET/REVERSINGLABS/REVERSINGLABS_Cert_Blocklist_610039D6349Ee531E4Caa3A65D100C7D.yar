import "pe"

rule REVERSINGLABS_Cert_Blocklist_610039D6349Ee531E4Caa3A65D100C7D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "de018b47-9fbd-590e-b3d1-b50029496718"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16248-L16264"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "e6b6a90cf40283d2e4d2d9c5732a078c9f2f117e3639ab5c0dd6c5323cb7c9ff"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Wemade Entertainment" and pe.signatures[i].serial=="61:00:39:d6:34:9e:e5:31:e4:ca:a3:a6:5d:10:0c:7d" and 1341792000<=pe.signatures[i].not_after)
}
