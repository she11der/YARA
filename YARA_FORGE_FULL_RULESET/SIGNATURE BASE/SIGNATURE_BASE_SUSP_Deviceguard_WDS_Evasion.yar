rule SIGNATURE_BASE_SUSP_Deviceguard_WDS_Evasion : FILE
{
	meta:
		description = "Detects WDS file used to circumvent Device Guard"
		author = "Florian Roth (Nextron Systems)"
		id = "469b60d4-43d3-5a85-aa51-e453d8c858c0"
		date = "2015-01-01"
		modified = "2023-01-06"
		reference = "http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_deviceguard_evasion.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4be9d7c34f7bafeb53db4fc1262a3692493b2253b0de7dc97480b01b62a9f12c"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "r @$ip=@$t0" ascii
		$s2 = ";eb @$t0+" ascii
		$s3 = ".foreach /pS" ascii

	condition:
		filesize <50KB and all of them
}
