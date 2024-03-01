import "pe"

rule REVERSINGLABS_Cert_Blocklist_5333D3079D8Afda715703775E1389991 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "4db299c6-5be9-5900-a944-07a0a41920a4"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L13186-L13202"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "98bd9d35c4e196a11943826115ab495833f7ef1d95f9736cc24255d6dd4fd21c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Trambambon LLC" and pe.signatures[i].serial=="53:33:d3:07:9d:8a:fd:a7:15:70:37:75:e1:38:99:91" and 1239148800<=pe.signatures[i].not_after)
}
