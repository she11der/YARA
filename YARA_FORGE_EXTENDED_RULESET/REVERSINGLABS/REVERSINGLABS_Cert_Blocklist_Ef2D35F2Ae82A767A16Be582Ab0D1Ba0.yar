import "pe"

rule REVERSINGLABS_Cert_Blocklist_Ef2D35F2Ae82A767A16Be582Ab0D1Ba0 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "dc8f49b8-fda2-510c-8374-3261e75d11a9"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5732-L5750"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "0709290aeb18bcb855518e150c2768c24ab311f5c727cdc4c40145b879ff88b6"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Workstage Limited" and (pe.signatures[i].serial=="00:ef:2d:35:f2:ae:82:a7:67:a1:6b:e5:82:ab:0d:1b:a0" or pe.signatures[i].serial=="ef:2d:35:f2:ae:82:a7:67:a1:6b:e5:82:ab:0d:1b:a0") and 1567123200<=pe.signatures[i].not_after)
}
