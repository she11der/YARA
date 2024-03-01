import "pe"

rule REVERSINGLABS_Cert_Blocklist_74Dbe83082E1B3Dfa29F9C24 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dbb75cf2-1b48-52f1-8d06-e35d48c4fea4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13222-L13238"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1fdf6471d0b869df1a8630108cdaf1cc97d33e91d4726073913cdc54c7cf0042"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EVANGEL TECHNOLOGY(HK) LIMITED" and pe.signatures[i].serial=="74:db:e8:30:82:e1:b3:df:a2:9f:9c:24" and 1468817578<=pe.signatures[i].not_after)
}
