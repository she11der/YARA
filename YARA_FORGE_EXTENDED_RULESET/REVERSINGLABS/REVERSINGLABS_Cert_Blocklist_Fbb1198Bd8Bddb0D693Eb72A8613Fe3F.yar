import "pe"

rule REVERSINGLABS_Cert_Blocklist_Fbb1198Bd8Bddb0D693Eb72A8613Fe3F : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f9983426-9f05-56e2-8ad0-1c5a48ab04be"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L8962-L8980"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2e004116d0f8df5a625b190127655926336fc74b4cce4ae40cd516a135e5d719"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Trade Hunters, s. r. o." and (pe.signatures[i].serial=="00:fb:b1:19:8b:d8:bd:db:0d:69:3e:b7:2a:86:13:fe:3f" or pe.signatures[i].serial=="fb:b1:19:8b:d8:bd:db:0d:69:3e:b7:2a:86:13:fe:3f") and 1620000000<=pe.signatures[i].not_after)
}
