import "pe"

rule REVERSINGLABS_Cert_Blocklist_B61B8E71514059Adc604Da05C283E514 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2587d30d-e9c8-599c-9cc4-4d4a7aa83c34"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6348-L6366"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "1255cef74082c9cad41ac8e7d62e740f69e6ba44171bb45655a68ee5db204e57"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APP DIVISION ApS" and (pe.signatures[i].serial=="00:b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14" or pe.signatures[i].serial=="b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14") and 1603328400<=pe.signatures[i].not_after)
}
