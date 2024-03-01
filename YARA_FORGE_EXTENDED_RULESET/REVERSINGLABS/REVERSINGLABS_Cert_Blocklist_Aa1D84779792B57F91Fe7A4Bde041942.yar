import "pe"

rule REVERSINGLABS_Cert_Blocklist_Aa1D84779792B57F91Fe7A4Bde041942 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8ec25296-2e51-53ec-a2f5-a25961079c27"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11842-L11860"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "682af8c799acaca531724c5b3184b855e64ec4531fcc333a485ba2f63331cdae"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AXIUM NORTHWESTERN HYDRO INC." and (pe.signatures[i].serial=="00:aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42" or pe.signatures[i].serial=="aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42") and 1639872000<=pe.signatures[i].not_after)
}
