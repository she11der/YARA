import "pe"

rule REVERSINGLABS_Cert_Blocklist_A7989F8Be0C82D35A19E7B3Dd4Be30E5 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "21d54d40-442e-50f5-a561-41b3d6239bac"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5290-L5308"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a50129908a471e6692bcf663abd5ef52861d4a46fdf528f39efe816ee6150edf"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Instamix Limited" and (pe.signatures[i].serial=="00:a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5" or pe.signatures[i].serial=="a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5") and 1598054400<=pe.signatures[i].not_after)
}
