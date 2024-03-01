import "pe"

rule REVERSINGLABS_Cert_Blocklist_73Ed1B2F4Bf8Dd37A8Ad9Bb775774592 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "19c9e100-b017-5b5c-8e8f-c94ea9e228c2"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14968-L14984"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "69865935e07ea255a5d690e170911b33574ea61550b00bebc2ceff91ba9a33da"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "5000 LIMITED" and pe.signatures[i].serial=="73:ed:1b:2f:4b:f8:dd:37:a8:ad:9b:b7:75:77:45:92" and 1528243200<=pe.signatures[i].not_after)
}
