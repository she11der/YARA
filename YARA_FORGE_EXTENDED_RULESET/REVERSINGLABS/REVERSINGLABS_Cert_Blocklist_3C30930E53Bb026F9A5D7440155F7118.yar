import "pe"

rule REVERSINGLABS_Cert_Blocklist_3C30930E53Bb026F9A5D7440155F7118 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "ad7d8be0-ecb1-508f-bfce-7a5cecfd4e2f"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13022-L13038"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "260a58669043d21ee0ffccbdee95c9d04ef338497685d42f1951660f658a164d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CPM Media, Ltd." and pe.signatures[i].serial=="3c:30:93:0e:53:bb:02:6f:9a:5d:74:40:15:5f:71:18" and 1064534400<=pe.signatures[i].not_after)
}
