import "pe"

rule REVERSINGLABS_Cert_Blocklist_E9756B3F38B1172Ea89Fdbdfdba5F979 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "77d7470c-0c60-5ef4-b1d9-35642c147afe"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14766-L14784"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "997a9433f907896d82f22ae323bf9cfe9aa04a2a49c5505e98adbb34277fcc15"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kreamer Ltd" and (pe.signatures[i].serial=="00:e9:75:6b:3f:38:b1:17:2e:a8:9f:db:df:db:a5:f9:79" or pe.signatures[i].serial=="e9:75:6b:3f:38:b1:17:2e:a8:9f:db:df:db:a5:f9:79") and 1492732800<=pe.signatures[i].not_after)
}
