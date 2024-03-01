rule SIGNATURE_BASE_Codoso_PGV_PVID_2 : FILE
{
	meta:
		description = "Detects Codoso APT PGV PVID Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "e4c00806-3092-5ec2-844f-b638c31fa6a5"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_codoso.yar#L315-L337"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "7eab3d398b5172127383047de7106a9713ec5b149f8e8ca1506b3382b007f648"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash2 = "b631553421aa17171cc47248adc110ca2e79eff44b5e5b0234d69b30cab104e3"
		hash3 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"

	strings:
		$s0 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
		$s1 = "regsvr32.exe /s \"%s\"" fullword ascii
		$s2 = "Help and Support" fullword ascii
		$s3 = "netsvcs" fullword ascii
		$s9 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" fullword ascii
		$s10 = "winlogon" fullword ascii
		$s11 = "System\\CurrentControlSet\\Services" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <907KB and all of them
}
