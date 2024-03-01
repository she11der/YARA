import "pe"

rule REVERSINGLABS_Cert_Blocklist_08622B9Dd9D78E67678Ecc21E026522E : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "66d942c7-ceb9-54e5-bccc-1adf641fd70e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8358-L8374"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "09507b09b035195b74434f56041588f67245fa097183228dffc612bb4901825b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kayak Republic af 2015 APS" and pe.signatures[i].serial=="08:62:2b:9d:d9:d7:8e:67:67:8e:cc:21:e0:26:52:2e" and 1611619200<=pe.signatures[i].not_after)
}
