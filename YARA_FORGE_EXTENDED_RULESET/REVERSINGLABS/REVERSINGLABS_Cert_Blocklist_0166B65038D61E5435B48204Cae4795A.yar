import "pe"

rule REVERSINGLABS_Cert_Blocklist_0166B65038D61E5435B48204Cae4795A : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "04bdefc5-ee4e-5a46-94d6-e3a5d8b56ce0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L2560-L2576"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "4e289eda4d5381250bcd6e36daade6f1e1803b6d16578d7eaee4454cef6981d0"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TOLGA KAPLAN" and pe.signatures[i].serial=="01:66:b6:50:38:d6:1e:54:35:b4:82:04:ca:e4:79:5a" and 1403999999<=pe.signatures[i].not_after)
}
