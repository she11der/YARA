import "pe"

rule REVERSINGLABS_Cert_Blocklist_57Fc55239F21F139978609E323097132 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "e71d575c-5a30-5158-80ee-3508cdaf5636"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12610-L12626"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "030bb847e524e672ee382e0284ba3f027920f60c70bbd153d4b9cdd2669e6a99"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aidem Media Limited" and pe.signatures[i].serial=="57:fc:55:23:9f:21:f1:39:97:86:09:e3:23:09:71:32" and 1501632000<=pe.signatures[i].not_after)
}
