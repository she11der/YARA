import "pe"

rule REVERSINGLABS_Cert_Blocklist_690910Dc89D7857C3500Fb74Bed2B08D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "7c427b1a-fbe9-5e97-9810-87863c70988d"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5482-L5498"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3c5da6238279296854eb95ecaed802f453e80c6bceb71c3fa587df0f7d40cf96"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OLIMP STROI, OOO" and pe.signatures[i].serial=="69:09:10:dc:89:d7:85:7c:35:00:fb:74:be:d2:b0:8d" and 1597276800<=pe.signatures[i].not_after)
}
