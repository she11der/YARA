import "pe"

rule REVERSINGLABS_Cert_Blocklist_06E842D3Ea6249D783D6B55E29C060C7 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "37829f07-c569-5e46-8b7a-2137c4c801e8"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3526-L3542"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9f71de0119527c8580f9e47e3fba07242814c5a537d727d4541fd7a802b0cb86"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PORT-SERVIS LTD, TOV" and pe.signatures[i].serial=="06:e8:42:d3:ea:62:49:d7:83:d6:b5:5e:29:c0:60:c7" and 1565568000<=pe.signatures[i].not_after)
}
