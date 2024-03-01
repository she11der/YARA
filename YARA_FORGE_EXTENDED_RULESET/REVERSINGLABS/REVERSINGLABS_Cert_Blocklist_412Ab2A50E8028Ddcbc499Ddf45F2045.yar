import "pe"

rule REVERSINGLABS_Cert_Blocklist_412Ab2A50E8028Ddcbc499Ddf45F2045 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "aabb3a66-5677-5359-9d81-92c8d4c7d910"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L14566-L14582"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "a5b85d13dee51d68af28394ecee3dcc2efe7add4d26c2a8033d1855b33ac6271"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ding Ruan" and pe.signatures[i].serial=="41:2a:b2:a5:0e:80:28:dd:cb:c4:99:dd:f4:5f:20:45" and 1479340800<=pe.signatures[i].not_after)
}
