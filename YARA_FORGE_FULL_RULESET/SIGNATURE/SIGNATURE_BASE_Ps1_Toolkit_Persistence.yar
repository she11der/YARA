rule SIGNATURE_BASE_Ps1_Toolkit_Persistence : FILE
{
	meta:
		description = "Auto-generated rule - file Persistence.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "38115391-75ac-5ba8-b31b-dcf4c66179b0"
		date = "2016-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/vysec/ps1-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_toolkit.yar#L113-L134"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bfe6b20fb712fcf7b45d0ef80075bc9a254867d2251109f377a378f887b38494"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"

	strings:
		$s1 = "\"`\"```$Filter=Set-WmiInstance -Class __EventFilter -Namespace ```\"root\\subscription```" ascii
		$s2 = "}=$PROFILE.AllUsersAllHosts;${" ascii
		$s3 = "C:\\PS> $ElevatedOptions = New-ElevatedPersistenceOption -Registry -AtStartup" ascii
		$s4 = "= gwmi Win32_OperatingSystem | select -ExpandProperty OSArchitecture" ascii
		$s5 = "-eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxADQAQwA='))))" ascii
		$s6 = "}=$PROFILE.CurrentUserAllHosts;${" ascii
		$s7 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
		$s8 = "[System.Text.AsciiEncoding]::ASCII.GetString($MZHeader)" fullword ascii

	condition:
		( uint16(0)==0xbbef and filesize <200KB and 2 of them ) or (4 of them )
}
