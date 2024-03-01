rule SIGNATURE_BASE_Invoke_Wmiexec_Gen_1
{
	meta:
		description = "Detects Invoke-WmiExec or Invoke-SmbExec"
		author = "Florian Roth (Nextron Systems)"
		id = "08b79c7d-c383-5891-af0f-31a92f1ed07d"
		date = "2017-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/Kevin-Robertson/Invoke-TheHash"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_invoke_thehash.yar#L32-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "12aeba5255527a337c49f1c4d1dc506a13ea02da69a8fc509c77bcb07c2135c8"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "140c23514dbf8043b4f293c501c2f9046efcc1c08630621f651cfedb6eed8b97"
		hash2 = "7565d376665e3cd07d859a5cf37c2332a14c08eb808cc5d187a7f0533dc69e07"

	strings:
		$x1 = "Invoke-WMIExec " ascii
		$x2 = "$target_count = [System.math]::Pow(2,(($target_address.GetAddressBytes().Length * 8) - $subnet_mask_split))" fullword ascii
		$s1 = "Import-Module $PWD\\Invoke-TheHash.ps1" fullword ascii
		$s2 = "Import-Module $PWD\\Invoke-SMBClient.ps1" fullword ascii
		$s3 = "$target_address_list = [System.Net.Dns]::GetHostEntry($target_long).AddressList" fullword ascii
		$x4 = "Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0" ascii

	condition:
		1 of them
}
