import "pe"

rule REVERSINGLABS_Cert_Blocklist_68C457D7495D2A8D0D7B9042836135C2 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a8ed2e72-d94e-5141-8ceb-181459a729ad"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13422-L13438"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3eb63f75f258eec611fa4288302f0ce5e47149ca876265a4a4b65dc33313aaa6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yuanyuan Zhang" and pe.signatures[i].serial=="68:c4:57:d7:49:5d:2a:8d:0d:7b:90:42:83:61:35:c2" and 1476921600<=pe.signatures[i].not_after)
}
