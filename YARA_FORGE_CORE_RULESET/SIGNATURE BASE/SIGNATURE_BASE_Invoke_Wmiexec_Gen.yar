rule SIGNATURE_BASE_Invoke_Wmiexec_Gen
{
	meta:
		description = "Auto-generated rule - from files Invoke-SMBClient.ps1, Invoke-SMBExec.ps1, Invoke-WMIExec.ps1, Invoke-WMIExec.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "08b79c7d-c383-5891-af0f-31a92f1ed07d"
		date = "2017-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_invoke_thehash.yar#L72-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "1ee79b7ea576adb71bde903756cda7af22e55eee9c4c3964cc9edc8930083fa2"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "56c6012c36aa863663fe5536d8b7fe4c460565d456ce2277a883f10d78893c01"
		hash2 = "674fc045dc198874f323ebdfb9e9ff2f591076fa6fac8d1048b5b8d9527c64cd"
		hash3 = "b41bd54bbf119d153e0878696cd5a944cbd4316c781dd8e390507b2ec2d949e7"

	strings:
		$s1 = "$NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)" fullword ascii
		$s2 = "$client_challenge = [String](1..8 | ForEach-Object {\"{0:X2}\" -f (Get-Random -Minimum 1 -Maximum 255)})" fullword ascii
		$s3 = "$NTLM_hash_bytes = $NTLM_hash_bytes.Split(\"-\") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}" fullword ascii

	condition:
		all of them
}
