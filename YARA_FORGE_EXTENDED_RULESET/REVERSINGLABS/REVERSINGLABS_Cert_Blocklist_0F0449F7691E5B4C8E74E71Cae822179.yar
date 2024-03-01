import "pe"

rule REVERSINGLABS_Cert_Blocklist_0F0449F7691E5B4C8E74E71Cae822179 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "17c99772-f2f9-56bc-be01-d9f62626a9ff"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L1708-L1724"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "f8d3593b357f27240a4399e877ae9044f783bb944ad47ec9fe8bbecc63be864c"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SBO INVEST" and pe.signatures[i].serial=="0f:04:49:f7:69:1e:5b:4c:8e:74:e7:1c:ae:82:21:79" and 1432079999<=pe.signatures[i].not_after)
}
