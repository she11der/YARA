import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ef9D0Cf071D463Cd63D13083046A7B8D : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "8751f71b-0ebb-5820-927c-684a5ae5ee7b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L6498-L6516"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "2923979811504f78a79a2480600285a2697845e51870a44ed231a81e79807121"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rubin LLC" and (pe.signatures[i].serial=="00:ef:9d:0c:f0:71:d4:63:cd:63:d1:30:83:04:6a:7b:8d" or pe.signatures[i].serial=="ef:9d:0c:f0:71:d4:63:cd:63:d1:30:83:04:6a:7b:8d") and 1605358307<=pe.signatures[i].not_after)
}
