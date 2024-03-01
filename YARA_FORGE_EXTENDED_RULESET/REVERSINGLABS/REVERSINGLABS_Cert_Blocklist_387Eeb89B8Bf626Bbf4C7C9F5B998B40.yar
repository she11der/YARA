import "pe"

rule REVERSINGLABS_Cert_Blocklist_387Eeb89B8Bf626Bbf4C7C9F5B998B40 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "2f4a26f2-689a-57bd-8028-d3554e339e60"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L9978-L9994"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2377eeb5316d25752443735e78d0ad7de398a2677f5a0fd45fd6e6c87720d49b"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ULTRA ACADEMY LTD" and pe.signatures[i].serial=="38:7e:eb:89:b8:bf:62:6b:bf:4c:7c:9f:5b:99:8b:40" and 1637141034<=pe.signatures[i].not_after)
}
