import "pe"

rule REVERSINGLABS_Cert_Blocklist_063Dcd7D7B0Bc77Cac844C7213Be3989 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "1bf4b84b-4a32-5908-8ccb-9fce2e5944e6"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L12536-L12552"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "091d00b0731f0a3d9917eee945249f001e4b5b1b603cad2fc21eed70ec86aa99"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HANNAH SISK LIMITED" and pe.signatures[i].serial=="06:3d:cd:7d:7b:0b:c7:7c:ac:84:4c:72:13:be:39:89" and 1656892801<=pe.signatures[i].not_after)
}
