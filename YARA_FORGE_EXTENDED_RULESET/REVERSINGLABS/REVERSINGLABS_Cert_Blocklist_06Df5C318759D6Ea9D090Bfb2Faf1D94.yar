import "pe"

rule REVERSINGLABS_Cert_Blocklist_06Df5C318759D6Ea9D090Bfb2Faf1D94 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a61e61c1-9fa0-5fd9-b197-bb9d1b68c8f4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11576-L11592"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5f151ee5781a15cca4394fdd8200162eae47e9d088a0b1551c9ed22ce11473a2"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SpiffyTech Inc." and pe.signatures[i].serial=="06:df:5c:31:87:59:d6:ea:9d:09:0b:fb:2f:af:1d:94" and 1634515201<=pe.signatures[i].not_after)
}
