import "pe"

rule REVERSINGLABS_Cert_Blocklist_E7E7F7180666546Ce7A8Da32119F5Ce1 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8984ac03-2646-54a1-a6d3-4c2cc72806e7"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L10898-L10916"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "940f6508208998593f309ffeeeda20ab475d427c952a14871b6e58e17d2a4c85"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "C\\xC3\\x94NG TY TNHH PDF SOFTWARE" and (pe.signatures[i].serial=="00:e7:e7:f7:18:06:66:54:6c:e7:a8:da:32:11:9f:5c:e1" or pe.signatures[i].serial=="e7:e7:f7:18:06:66:54:6c:e7:a8:da:32:11:9f:5c:e1") and 1661558399<=pe.signatures[i].not_after)
}
