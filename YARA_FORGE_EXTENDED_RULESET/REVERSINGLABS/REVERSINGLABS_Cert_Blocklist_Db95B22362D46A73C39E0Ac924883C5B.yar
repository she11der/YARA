import "pe"

rule REVERSINGLABS_Cert_Blocklist_Db95B22362D46A73C39E0Ac924883C5B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "527b7963-340e-5d8f-b7e1-1269c0073ec9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10218-L10236"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "895983bcb7f3a0c5ce54504f4a2ff8d652137434b8951380d756de6556d0844e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPSLTD PLYMOUTH LTD" and (pe.signatures[i].serial=="00:db:95:b2:23:62:d4:6a:73:c3:9e:0a:c9:24:88:3c:5b" or pe.signatures[i].serial=="db:95:b2:23:62:d4:6a:73:c3:9e:0a:c9:24:88:3c:5b") and 1621296000<=pe.signatures[i].not_after)
}
