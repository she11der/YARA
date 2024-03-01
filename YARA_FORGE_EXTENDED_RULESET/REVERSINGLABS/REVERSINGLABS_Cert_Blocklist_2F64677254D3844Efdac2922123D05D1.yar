import "pe"

rule REVERSINGLABS_Cert_Blocklist_2F64677254D3844Efdac2922123D05D1 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "de9ef02d-a723-5013-9f91-e394edc23855"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6462-L6478"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f9f1f629e03563ece0fe5186b199e2f030dce7f58fb259de1aeb7387c76fa902"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ORGANICUP ApS" and pe.signatures[i].serial=="2f:64:67:72:54:d3:84:4e:fd:ac:29:22:12:3d:05:d1" and 1605640092<=pe.signatures[i].not_after)
}
