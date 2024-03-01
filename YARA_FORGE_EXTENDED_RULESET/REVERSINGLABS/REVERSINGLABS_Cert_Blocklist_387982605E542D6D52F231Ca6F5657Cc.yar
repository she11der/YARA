import "pe"

rule REVERSINGLABS_Cert_Blocklist_387982605E542D6D52F231Ca6F5657Cc : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2d5731e1-b18b-544e-ae14-40d70b679618"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14656-L14672"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d55cfd45bc0d330c0ed433a882874e4633ffbaa0d68288bea9058fe269d75ed9"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jiang Liu" and pe.signatures[i].serial=="38:79:82:60:5e:54:2d:6d:52:f2:31:ca:6f:56:57:cc" and 1475884800<=pe.signatures[i].not_after)
}
