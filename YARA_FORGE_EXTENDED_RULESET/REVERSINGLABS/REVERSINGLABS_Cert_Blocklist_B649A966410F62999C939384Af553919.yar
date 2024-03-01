import "pe"

rule REVERSINGLABS_Cert_Blocklist_B649A966410F62999C939384Af553919 : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "03533c22-eb16-546c-af55-675af9c833ce"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L11290-L11308"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "623a2f931198eacf44fd233065e96a4dcadb5b3bbc7ca56df2b6ae9eafc4faa5"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "F.A.T. SARL" and (pe.signatures[i].serial=="00:b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19" or pe.signatures[i].serial=="b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19") and 1590537600<=pe.signatures[i].not_after)
}
