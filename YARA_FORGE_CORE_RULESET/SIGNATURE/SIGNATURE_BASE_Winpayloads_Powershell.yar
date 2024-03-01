rule SIGNATURE_BASE_Winpayloads_Powershell : FILE
{
	meta:
		description = "Detects WinPayloads PowerShell Payload"
		author = "Florian Roth (Nextron Systems)"
		id = "8b6b8823-4656-5b0d-9a1e-84045287f5bf"
		date = "2017-07-11"
		modified = "2023-12-05"
		reference = "https://github.com/nccgroup/Winpayloads"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_winpayloads.yar#L12-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e9e75f7190327f08c5e204977c6714c93951a6db0ddf000c8b37db37131b9def"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "011eba8f18b66634f6eb47527b4ceddac2ae615d6861f89a35dbb9fc591cae8e"

	strings:
		$x1 = "$Base64Cert = 'MIIJeQIBAzCCCT8GCSqGSIb3DQEHAaCCCTAEggksMIIJKDCCA98GCSqGSIb3DQEHBqCCA9AwggPMAgEAMIIDxQYJKoZIhvcNAQcBMBwGCiqGSIb3D" ascii
		$x2 = "powershell -w hidden -noni -enc SQBF" fullword ascii nocase
		$x3 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwA" ascii
		$x4 = "powershell.exe -WindowStyle Hidden -enc JABjAGwAaQBlAG4AdAA" ascii

	condition:
		filesize <10KB and 1 of them
}
