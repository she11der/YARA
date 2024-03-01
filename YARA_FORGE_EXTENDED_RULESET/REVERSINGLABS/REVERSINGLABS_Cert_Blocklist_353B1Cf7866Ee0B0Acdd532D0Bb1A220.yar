import "pe"

rule REVERSINGLABS_Cert_Blocklist_353B1Cf7866Ee0B0Acdd532D0Bb1A220 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "20b95b80-94a9-51c3-9c6c-2a0ef75b0c0b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L15972-L15988"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "aa8f0fe1517134b6e562c2accc46420a4f0afd77c3a7bbe98d551c54e68ed4c7"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Network Freak Limited" and pe.signatures[i].serial=="35:3b:1c:f7:86:6e:e0:b0:ac:dd:53:2d:0b:b1:a2:20" and 1558915200<=pe.signatures[i].not_after)
}
