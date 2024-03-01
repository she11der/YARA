import "pe"

rule REVERSINGLABS_Cert_Blocklist_881573Fc67Ff7395Dde5Bccfbce5B088 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "d188c65c-ee7b-586f-95f0-8de5b506c325"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11180-L11198"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "ce489a4a2f07181d6fbf295f426deeaf51310e061bac2e56d65b37eeb397ff9a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Trade in Brasil s.r.o." and (pe.signatures[i].serial=="00:88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88" or pe.signatures[i].serial=="88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88") and 1620000000<=pe.signatures[i].not_after)
}
