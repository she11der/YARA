import "pe"

rule REVERSINGLABS_Cert_Blocklist_569E03988Af60D80Ce60728940850D9B : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "a4432990-8c2f-523c-8a9d-cba578aaefc5"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5824-L5842"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "3ea894d9e088c2123f9ec87cbf097e2275fae18cad26e926641fe64921808b1e"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OORT inc." and (pe.signatures[i].serial=="00:56:9e:03:98:8a:f6:0d:80:ce:60:72:89:40:85:0d:9b" or pe.signatures[i].serial=="56:9e:03:98:8a:f6:0d:80:ce:60:72:89:40:85:0d:9b") and 1601006510<=pe.signatures[i].not_after)
}
