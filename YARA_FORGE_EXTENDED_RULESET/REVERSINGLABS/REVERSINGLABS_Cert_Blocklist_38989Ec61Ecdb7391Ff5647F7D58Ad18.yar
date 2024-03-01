import "pe"

rule REVERSINGLABS_Cert_Blocklist_38989Ec61Ecdb7391Ff5647F7D58Ad18 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1841bbd1-4c7a-5b89-8c63-58d8a3ae1cef"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12256-L12272"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1795812d4daa458b157280cac7a9b13e9b67a2d78eac077691bbce2bf8aeec34"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RotA Games ApS" and pe.signatures[i].serial=="38:98:9e:c6:1e:cd:b7:39:1f:f5:64:7f:7d:58:ad:18" and 1613088000<=pe.signatures[i].not_after)
}
