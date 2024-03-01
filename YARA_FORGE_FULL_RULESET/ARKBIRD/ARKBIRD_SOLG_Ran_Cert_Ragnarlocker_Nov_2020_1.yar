import "pe"

rule ARKBIRD_SOLG_Ran_Cert_Ragnarlocker_Nov_2020_1 : FILE
{
	meta:
		description = "Detect certificates and VMProtect used for the Ragnarlocker ransomware (Nov 2020)"
		author = "Arkbird_SOLG"
		id = "85d51804-eebd-5353-8bd9-01756e7f7d07"
		date = "2020-11-26"
		modified = "2020-11-27"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-11-27/Ran_RagnarLocker_Nov_2020_1.yar#L35-L55"
		license_url = "N/A"
		logic_hash = "8171128426b48102457f5ba0771b27aaf5f4562293aff04c256bd5bd721a908e"
		score = 50
		quality = 75
		tags = "FILE"
		level = "Experimental"
		hash1 = "afab912c41c920c867f1b2ada34114b22dcc9c5f3666edbfc4e9936c29a17a68"
		hash2 = "9416e5a57e6de00c685560fa9fee761126569d123f62060792bf2049ebba4151"

	strings:
		$vmp0 = { 2E 76 6D 70 30 00 00 00 }
		$vmp1 = { 2E 76 6D 70 31 00 00 00 }

	condition:
		uint16(0)==0x5a4d and filesize >5000KB and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "GlobalSign" and pe.signatures[i].serial=="68:65:29:4f:67:f0:c3:bb:2e:19:1f:75") and $vmp0 in (0x100..0x300) and $vmp1 in (0x100..0x300)
}
