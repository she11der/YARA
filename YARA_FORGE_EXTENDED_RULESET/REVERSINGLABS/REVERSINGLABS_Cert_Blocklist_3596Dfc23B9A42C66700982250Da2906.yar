import "pe"

rule REVERSINGLABS_Cert_Blocklist_3596Dfc23B9A42C66700982250Da2906 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "15c3551f-7b08-5e7f-a540-68b3eccac316"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L16998-L17014"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1b69bf520fde5255069cf8752d5c67716e9bc297ddde1566551a563a563197ea"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Open Source Developer, Song WU" and pe.signatures[i].serial=="35:96:df:c2:3b:9a:42:c6:67:00:98:22:50:da:29:06" and 1397219344<=pe.signatures[i].not_after)
}
