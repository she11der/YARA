rule SIGNATURE_BASE_Ps1_Toolkit_Powerup_2 : FILE
{
	meta:
		description = "Auto-generated rule - from files PowerUp.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "11322a66-67d4-574b-acef-35d06e6f95f4"
		date = "2016-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/vysec/ps1-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_toolkit.yar#L183-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8cbd86f103d8b49e72787cbb85fc97e6a02d5332039ce29359cb673c273760b7"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"

	strings:
		$s1 = "if($MyConString -like $([Text.Encoding]::Unicode.GetString([Convert]::" ascii
		$s2 = "FromBase64String('KgBwAGEAcwBzAHcAbwByAGQAKgA=')))) {" ascii
		$s3 = "$Null = Invoke-ServiceStart" ascii
		$s4 = "Write-Warning \"[!] Access to service $" ascii
		$s5 = "} = $MyConString.Split(\"=\")[1].Split(\";\")[0]" ascii
		$s6 = "} += \"net localgroup ${" ascii

	condition:
		( uint16(0)==0xbbef and filesize <2000KB and 2 of them ) or (4 of them )
}
