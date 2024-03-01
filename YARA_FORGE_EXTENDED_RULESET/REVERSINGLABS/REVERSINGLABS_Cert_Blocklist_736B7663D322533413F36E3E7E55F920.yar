import "pe"

rule REVERSINGLABS_Cert_Blocklist_736B7663D322533413F36E3E7E55F920 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1991779a-8b5d-5188-8a36-c8451923e88f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13458-L13474"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "44e86319106a4bf8edba6c1be2f90d68b3d1ef4591f0cc23921a0dc4da4a407b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Net Technology" and pe.signatures[i].serial=="73:6b:76:63:d3:22:53:34:13:f3:6e:3e:7e:55:f9:20" and 1159488000<=pe.signatures[i].not_after)
}
