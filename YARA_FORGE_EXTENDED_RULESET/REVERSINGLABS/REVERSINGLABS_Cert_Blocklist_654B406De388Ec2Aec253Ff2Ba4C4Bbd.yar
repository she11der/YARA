import "pe"

rule REVERSINGLABS_Cert_Blocklist_654B406De388Ec2Aec253Ff2Ba4C4Bbd : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "9820112d-d59b-57e7-ae78-7b427f70d529"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13656-L13672"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a1aadaded55c8b0d85ac09ba9ab27fefaeec2969cdabaf26ff0c41bf33422ddc"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yijiajian (Amoy) Jiankan Tech Co.,LTD." and pe.signatures[i].serial=="65:4b:40:6d:e3:88:ec:2a:ec:25:3f:f2:ba:4c:4b:bd" and 1398902400<=pe.signatures[i].not_after)
}
