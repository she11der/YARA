import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ca4822E6905Aa4Fca9E28523F04F14A3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "004454a0-20f9-58f5-8c24-8097f7586c5b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7050-L7068"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "9633f3494e9ece3a698d47c5ba2b7ee7f82cee4be36ac418c969c36285c4963c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ELISTREID, OOO" and (pe.signatures[i].serial=="00:ca:48:22:e6:90:5a:a4:fc:a9:e2:85:23:f0:4f:14:a3" or pe.signatures[i].serial=="ca:48:22:e6:90:5a:a4:fc:a9:e2:85:23:f0:4f:14:a3") and 1614643200<=pe.signatures[i].not_after)
}
