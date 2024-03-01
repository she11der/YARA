import "pe"

rule REVERSINGLABS_Cert_Blocklist_F360F7Ad0Ed065Fec0B44F98E04481A0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "96219c86-f463-5f11-950d-ca2af75d5559"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5424-L5442"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2a25f1121f492dec461e570ff56acb0e3957cdf9100002f2ff0b6c3d3b35fee5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MEHANIKUM OOO" and (pe.signatures[i].serial=="00:f3:60:f7:ad:0e:d0:65:fe:c0:b4:4f:98:e0:44:81:a0" or pe.signatures[i].serial=="f3:60:f7:ad:0e:d0:65:fe:c0:b4:4f:98:e0:44:81:a0") and 1599031121<=pe.signatures[i].not_after)
}
