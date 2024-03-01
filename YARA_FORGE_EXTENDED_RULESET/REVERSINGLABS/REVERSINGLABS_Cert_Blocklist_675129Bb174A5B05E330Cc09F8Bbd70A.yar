import "pe"

rule REVERSINGLABS_Cert_Blocklist_675129Bb174A5B05E330Cc09F8Bbd70A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "97046206-efc4-58dd-a9df-4966bad3902d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L3470-L3486"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "d989ea5233e8a64bffa0e29645c3458ef1f5173158ced7814c3b473b92ef49f4"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALEX & CO PTY LIMITED" and pe.signatures[i].serial=="67:51:29:bb:17:4a:5b:05:e3:30:cc:09:f8:bb:d7:0a" and 1565568000<=pe.signatures[i].not_after)
}
