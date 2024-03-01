import "pe"

rule REVERSINGLABS_Cert_Blocklist_56E22B992B4C7F1Afeac1D63B492Bf54 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "28609e75-47cb-5017-bb92-046a9e8931c6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1672-L1688"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ef058c0ec352260fa3db0fc74331d1da3c9eb8d161cef7635632fd7c569198c6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Open Source Developer, Hetem Ramadani" and pe.signatures[i].serial=="56:e2:2b:99:2b:4c:7f:1a:fe:ac:1d:63:b4:92:bf:54" and 1435622399<=pe.signatures[i].not_after)
}
