import "pe"

rule REVERSINGLABS_Cert_Blocklist_0883Db137021B51F3A2A08A76A4Bc066 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "792111be-7c8a-53f5-9ec3-e1f25f083666"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10408-L10424"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "5e3c8654169830790665992f5d7669d0ca6c1c8048580b3ae70331ad2a763a6c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Divertida Creative Limited" and pe.signatures[i].serial=="08:83:db:13:70:21:b5:1f:3a:2a:08:a7:6a:4b:c0:66" and 1627430400<=pe.signatures[i].not_after)
}
