import "pe"

rule REVERSINGLABS_Cert_Blocklist_4463D8B31E0F87C14233D4D0D2C487A0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "eefd6fa2-7ed7-51d0-bddd-90f0727a93cc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14638-L14654"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "04ce664fceb4a617294e860d5364d8a4ce8e055fd2baebb8be69f258d9c70ac7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Yu Bao" and pe.signatures[i].serial=="44:63:d8:b3:1e:0f:87:c1:42:33:d4:d0:d2:c4:87:a0" and 1477612800<=pe.signatures[i].not_after)
}
