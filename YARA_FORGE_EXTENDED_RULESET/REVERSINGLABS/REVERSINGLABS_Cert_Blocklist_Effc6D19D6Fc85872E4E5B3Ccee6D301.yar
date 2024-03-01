import "pe"

rule REVERSINGLABS_Cert_Blocklist_Effc6D19D6Fc85872E4E5B3Ccee6D301 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "56114e31-2e9b-5d16-8435-708bbb2687cc"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12856-L12874"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a746c4193f1264cb96eae0ea85c2c76b5caf3b72ca950f76af426b4d68d210b3"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "C\\xC3\\x93IR IP LIMITED" and (pe.signatures[i].serial=="00:ef:fc:6d:19:d6:fc:85:87:2e:4e:5b:3c:ce:e6:d3:01" or pe.signatures[i].serial=="ef:fc:6d:19:d6:fc:85:87:2e:4e:5b:3c:ce:e6:d3:01") and 1572307200<=pe.signatures[i].not_after)
}
