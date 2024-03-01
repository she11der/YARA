import "pe"

rule REVERSINGLABS_Cert_Blocklist_02C5351936Abe405Ac760228A40387E8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6a1e5115-ac72-57a3-8418-7c81f38f76af"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L4384-L4400"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5a990f8d1a3f467cdafa0f625bc162745d9201e15ce43fdc93cd6b1730572e89"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RESURS-RM OOO" and pe.signatures[i].serial=="02:c5:35:19:36:ab:e4:05:ac:76:02:28:a4:03:87:e8" and 1589932801<=pe.signatures[i].not_after)
}
