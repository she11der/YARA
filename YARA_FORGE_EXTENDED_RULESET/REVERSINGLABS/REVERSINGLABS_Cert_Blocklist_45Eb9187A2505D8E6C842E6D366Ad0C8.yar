import "pe"

rule REVERSINGLABS_Cert_Blocklist_45Eb9187A2505D8E6C842E6D366Ad0C8 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1b8390aa-16b9-558b-aee8-e30fc7100af4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L7730-L7746"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4ae755e814ae2488d4bd6b8136ab6d78e4809a2ddacb7f88cf1d2b64c1488898"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BAKERA s.r.o." and pe.signatures[i].serial=="45:eb:91:87:a2:50:5d:8e:6c:84:2e:6d:36:6a:d0:c8" and 1607040000<=pe.signatures[i].not_after)
}
