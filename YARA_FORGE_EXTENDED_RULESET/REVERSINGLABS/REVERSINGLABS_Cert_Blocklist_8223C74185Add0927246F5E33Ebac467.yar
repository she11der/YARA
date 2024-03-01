import "pe"

rule REVERSINGLABS_Cert_Blocklist_8223C74185Add0927246F5E33Ebac467 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dfe87130-7b2f-5f8a-8c2d-8653c2bd0cd3"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12704-L12722"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f700b4f7cdfda9f678c3a5259d4293640c50567ec277c5b3db69756534e2007f"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TOV Virikton" and (pe.signatures[i].serial=="00:82:23:c7:41:85:ad:d0:92:72:46:f5:e3:3e:ba:c4:67" or pe.signatures[i].serial=="82:23:c7:41:85:ad:d0:92:72:46:f5:e3:3e:ba:c4:67") and 1463616000<=pe.signatures[i].not_after)
}
