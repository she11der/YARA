import "pe"

rule REVERSINGLABS_Cert_Blocklist_Fbb96A90B6718810311767Ca25Ab1E48 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "77319b9c-6075-5ac7-958c-d76916873e85"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9688-L9706"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "431e3364a42b272d9b71b92dee44cc185ef034a45a0b72bbda82cf7e9b29c355"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rakurs LLC" and (pe.signatures[i].serial=="00:fb:b9:6a:90:b6:71:88:10:31:17:67:ca:25:ab:1e:48" or pe.signatures[i].serial=="fb:b9:6a:90:b6:71:88:10:31:17:67:ca:25:ab:1e:48") and 1636046757<=pe.signatures[i].not_after)
}
