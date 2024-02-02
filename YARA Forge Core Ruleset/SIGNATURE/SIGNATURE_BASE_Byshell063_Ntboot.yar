rule SIGNATURE_BASE_Byshell063_Ntboot
{
	meta:
		description = "Webshells Auto-generated - file ntboot.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "7d1f39f6-04f1-51ee-b125-c35af8ae4c0c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7822-L7836"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "99b5f49db6d6d9a9faeffb29fd8e6d8c"
		logic_hash = "2fdc930eacb87d02ebe69a2b64df4103bd0f3417a76f1b2922b3d4cd4c0dffe9"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtBoot"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "Dumping Description to Registry..."
		$s3 = "Opening Service .... Failure !"

	condition:
		all of them
}