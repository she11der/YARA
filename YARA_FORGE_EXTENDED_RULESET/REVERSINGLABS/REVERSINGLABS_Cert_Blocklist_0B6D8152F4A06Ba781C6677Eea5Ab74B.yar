import "pe"

rule REVERSINGLABS_Cert_Blocklist_0B6D8152F4A06Ba781C6677Eea5Ab74B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dacac5fe-00dc-5080-a725-9ef69473c45e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3324-L3340"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "bd20cf8e4cab2117361dbe05ae2efe813e7f55667b1f3825cd893313d98dcb5f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GLARYSOFT LTD" and pe.signatures[i].serial=="0b:6d:81:52:f4:a0:6b:a7:81:c6:67:7e:ea:5a:b7:4b" and 1568246400<=pe.signatures[i].not_after)
}
