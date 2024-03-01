import "pe"

rule REVERSINGLABS_Cert_Blocklist_846F77D9919Fc4405Aefe1701309Bd67 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c326fbf0-2d95-5aa1-9ae4-6cb04b9c2212"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8982-L9000"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "6739049a61183d506daf9aaf44a3b15cbf2234c6af307ec95bc07fa3d8501105"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IPM Skupina d.o.o." and (pe.signatures[i].serial=="00:84:6f:77:d9:91:9f:c4:40:5a:ef:e1:70:13:09:bd:67" or pe.signatures[i].serial=="84:6f:77:d9:91:9f:c4:40:5a:ef:e1:70:13:09:bd:67") and 1621382400<=pe.signatures[i].not_after)
}
