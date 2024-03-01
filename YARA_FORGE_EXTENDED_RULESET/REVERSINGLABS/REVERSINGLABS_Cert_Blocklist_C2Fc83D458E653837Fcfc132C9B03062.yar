import "pe"

rule REVERSINGLABS_Cert_Blocklist_C2Fc83D458E653837Fcfc132C9B03062 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "135d638c-9ee5-52cf-a6e7-c12e4feef594"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11686-L11704"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "836cec8d8396680dd64f95d4dd41f7f5876cb4268d983238a01d2e0990cce74a"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Vertical" and (pe.signatures[i].serial=="00:c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62" or pe.signatures[i].serial=="c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62") and 1602201600<=pe.signatures[i].not_after)
}
