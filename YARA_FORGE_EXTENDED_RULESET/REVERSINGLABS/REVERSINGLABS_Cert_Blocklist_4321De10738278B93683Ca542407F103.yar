import "pe"

rule REVERSINGLABS_Cert_Blocklist_4321De10738278B93683Ca542407F103 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "bf800655-cde4-59fa-9574-1055522fe074"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14530-L14546"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2787375605310877891ef924268f4660d1c8aa020e00674c1b1d7eb3c4f5b2fb"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "We Build Toolbars LLC" and pe.signatures[i].serial=="43:21:de:10:73:82:78:b9:36:83:ca:54:24:07:f1:03" and 1367884800<=pe.signatures[i].not_after)
}
