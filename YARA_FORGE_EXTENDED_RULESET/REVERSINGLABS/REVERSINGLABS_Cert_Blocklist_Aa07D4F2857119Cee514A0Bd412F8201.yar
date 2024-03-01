import "pe"

rule REVERSINGLABS_Cert_Blocklist_Aa07D4F2857119Cee514A0Bd412F8201 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "6bb83f26-90f5-587f-8c69-fa06beaead3e"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12102-L12120"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "fbbea89f2070b2a527bba6199022fbffd269e664b000988a59adf4ca0d4a9f22"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HANGA GIP d.o.o." and (pe.signatures[i].serial=="00:aa:07:d4:f2:85:71:19:ce:e5:14:a0:bd:41:2f:82:01" or pe.signatures[i].serial=="aa:07:d4:f2:85:71:19:ce:e5:14:a0:bd:41:2f:82:01") and 1615766400<=pe.signatures[i].not_after)
}
