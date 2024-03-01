import "pe"

rule REVERSINGLABS_Cert_Blocklist_039668034826Df47E6207Ec9Daed57C3 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "c2a3477a-a4cf-586e-ba70-555cc577ab2c"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5752-L5768"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "792860feec6e599ba22ae3869ef132cf5b7be2e0572e23503e293444fd7c382d"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CHOO FSP, LLC" and pe.signatures[i].serial=="03:96:68:03:48:26:df:47:e6:20:7e:c9:da:ed:57:c3" and 1601424001<=pe.signatures[i].not_after)
}
