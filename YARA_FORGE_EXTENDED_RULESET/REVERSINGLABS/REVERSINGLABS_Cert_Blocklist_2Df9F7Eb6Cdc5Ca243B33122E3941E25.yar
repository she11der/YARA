import "pe"

rule REVERSINGLABS_Cert_Blocklist_2Df9F7Eb6Cdc5Ca243B33122E3941E25 : INFO FILE
{
	meta:
		description = "The digital certificate has leaked."
		author = "ReversingLabs"
		id = "da1895fd-ec29-513d-b8ae-2317f84b8280"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1344-L1360"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "703eccd5573fe42f03ec82887660d50e942156d840394746c90ba87d82507803"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Adobe Systems" and pe.signatures[i].serial=="2d:f9:f7:eb:6c:dc:5c:a2:43:b3:31:22:e3:94:1e:25" and 1341792000<=pe.signatures[i].not_after)
}
