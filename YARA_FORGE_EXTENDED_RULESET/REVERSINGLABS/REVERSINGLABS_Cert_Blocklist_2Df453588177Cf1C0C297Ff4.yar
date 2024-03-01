import "pe"

rule REVERSINGLABS_Cert_Blocklist_2Df453588177Cf1C0C297Ff4 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c3a18989-239e-56d7-b1c2-92895c02b7d8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16672-L16688"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "b0c82388fd87a89841d190ce4020cc5a2ea21c9d765ceca6bc25d64162479231"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shenzhen Yunhuitianxia Technology Co.,Ltd." and pe.signatures[i].serial=="2d:f4:53:58:81:77:cf:1c:0c:29:7f:f4" and 1479735173<=pe.signatures[i].not_after)
}
