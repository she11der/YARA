import "pe"

rule REVERSINGLABS_Cert_Blocklist_Cfac705C7E6845904F99995324F7562C : INFO FILE
{
	meta:
		description = "Certificate used for digitally signing malware."
		author = "ReversingLabs"
		id = "42aa3105-a077-5962-8d5d-50429254582b"
		date = "2023-11-08"
		modified = "2023-11-08"
		reference = "ReversingLabs"
		source_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/yara/certificate/blocklist.yara#L5270-L5288"
		license_url = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/6db04d21a54cece1e65f12769dd0dd24d44def78/LICENSE"
		logic_hash = "68bcfe60c2e7154f427c20d0471ede99e55c8200149a4438d5a2a75982fcd419"
		score = 75
		quality = 90
		tags = "INFO, FILE"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		category = "INFO"
		importance = 25

	condition:
		uint16(0)==0x5A4D and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HMWOCFPSDLAFMFZIVD" and (pe.signatures[i].serial=="cf:ac:70:5c:7e:68:45:90:4f:99:99:53:24:f7:56:2c" or pe.signatures[i].serial=="30:53:8f:a3:81:97:ba:6f:b0:66:66:ac:db:08:a9:d4") and 1601918720<=pe.signatures[i].not_after)
}
