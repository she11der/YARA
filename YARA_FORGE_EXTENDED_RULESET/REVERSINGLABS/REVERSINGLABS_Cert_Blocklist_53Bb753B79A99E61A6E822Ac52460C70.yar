import "pe"

rule REVERSINGLABS_Cert_Blocklist_53Bb753B79A99E61A6E822Ac52460C70 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6339d548-775b-52b9-84c5-a79de23a16b2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2672-L2688"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "24ff4f46fa6e85c25e130459f9b8d6907cf6cd51098e0cf45ec11d54d7de509b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xEB\\x8D\\xB0\\xEC\\x8A\\xA4\\xED\\x81\\xAC\\xED\\x83\\x91\\xEC\\x95\\x84\\xEC\\x9D\\xB4\\xEC\\xBD\\x98" and pe.signatures[i].serial=="53:bb:75:3b:79:a9:9e:61:a6:e8:22:ac:52:46:0c:70" and 1400543999<=pe.signatures[i].not_after)
}
