rule SIGNATURE_BASE_Invoke_Smbexec_Invoke_Wmiexec_1
{
	meta:
		description = "Auto-generated rule - from files Invoke-SMBExec.ps1, Invoke-WMIExec.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "fd1c6599-028d-5535-beb8-5b2658481b97"
		date = "2017-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_invoke_thehash.yar#L53-L70"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "feb2973cd7e2c221cd91ec543f1d943cf1b5d5d18fe74c8f7e58341f76f95b51"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "674fc045dc198874f323ebdfb9e9ff2f591076fa6fac8d1048b5b8d9527c64cd"
		hash2 = "b41bd54bbf119d153e0878696cd5a944cbd4316c781dd8e390507b2ec2d949e7"

	strings:
		$s1 = "$process_ID = $process_ID -replace \"-00-00\",\"\"" fullword ascii
		$s2 = "Write-Output \"$Target did not respond\"" fullword ascii
		$s3 = "[Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)" fullword ascii

	condition:
		all of them
}
