import "pe"

rule REVERSINGLABS_Cert_Blocklist_1E5Efa53A14599Cc82F56F0790E20B17 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "f87dac0c-4b46-5b30-a715-f21e7c3a98e0"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11442-L11458"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "78cbfeb5d7b58029a5b4107f2a59e892ff9d71788cf74e88ac823cb85ba35a94"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Storeks LLC" and pe.signatures[i].serial=="1e:5e:fa:53:a1:45:99:cc:82:f5:6f:07:90:e2:0b:17" and 1623196800<=pe.signatures[i].not_after)
}
