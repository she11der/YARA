import "pe"

rule REVERSINGLABS_Cert_Blocklist_04F380F97579F1702A85E0169Bbdfd78 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "860027ff-2df2-5519-afde-60ebee270290"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1906-L1922"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "73dc6e36fdaf5c80b33f20f2a9157805ce1d0218f3898104de16522ee9cfd51b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GRANIFLOR" and pe.signatures[i].serial=="04:f3:80:f9:75:79:f1:70:2a:85:e0:16:9b:bd:fd:78" and 1454889599<=pe.signatures[i].not_after)
}
