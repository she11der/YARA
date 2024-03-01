import "pe"

rule REVERSINGLABS_Cert_Blocklist_09813Ee7318452C28A1F6426D1Cee12D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "db3c1992-b6a1-5aaf-ae3a-c626b531529a"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1996-L2012"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "89eb019192f822f9fe070403161d81e425fb8acdbc80e55fa516b5607eb8f8c7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Saly Younes" and pe.signatures[i].serial=="09:81:3e:e7:31:84:52:c2:8a:1f:64:26:d1:ce:e1:2d" and 1455667199<=pe.signatures[i].not_after)
}
