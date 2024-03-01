import "pe"

rule REVERSINGLABS_Cert_Blocklist_06Fa27A121Cc82230C3013Ee634B6C62 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4520e544-7a41-5dde-b90b-46cf3349297c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10296-L10312"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "23ac7a97e7632536ed27cf9078b6bc1a734f1e991a20a228734b45117582f367"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Zimmi Consulting Inc" and pe.signatures[i].serial=="06:fa:27:a1:21:cc:82:23:0c:30:13:ee:63:4b:6c:62" and 1645142401<=pe.signatures[i].not_after)
}
