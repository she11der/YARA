import "pe"

rule REVERSINGLABS_Cert_Blocklist_86E5A9B9E89E5075C475006D0Ca03832 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f3058f56-dcbb-532a-b914-5ac0e6d70e6e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3696-L3714"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5ba0b0f1b104eb11023590b8ef2b9cc747372bc9310a754694d45d3b3ce293e9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BlueMarble GmbH" and (pe.signatures[i].serial=="00:86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32" or pe.signatures[i].serial=="86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32") and 1574791194<=pe.signatures[i].not_after)
}
