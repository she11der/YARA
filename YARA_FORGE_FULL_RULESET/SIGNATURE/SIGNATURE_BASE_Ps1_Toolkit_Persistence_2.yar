rule SIGNATURE_BASE_Ps1_Toolkit_Persistence_2 : FILE
{
	meta:
		description = "Auto-generated rule - from files Persistence.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "d79c328b-4471-52bb-882c-12d2e1302c1e"
		date = "2016-09-04"
		modified = "2023-12-05"
		reference = "https://github.com/vysec/ps1-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_toolkit.yar#L204-L226"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "47d1c3593edeba02e1c08cc53b4ba3d375b73dd04816b84e807e28be2bcf917e"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"

	strings:
		$s1 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
		$s2 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBEAGEAaQBsAHkA')" ascii
		$s3 = "FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA==')" ascii
		$s4 = "[Parameter( ParameterSetName = 'ScheduledTaskAtLogon', Mandatory = $True )]" ascii
		$s5 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBBAHQATABvAGcAbwBuAA==')))" ascii
		$s6 = "[Parameter( ParameterSetName = 'PermanentWMIAtStartup', Mandatory = $True )]" fullword ascii
		$s7 = "FromBase64String('TQBlAHQAaABvAGQA')" ascii
		$s8 = "FromBase64String('VAByAGkAZwBnAGUAcgA=')" ascii
		$s9 = "[Runtime.InteropServices.CallingConvention]::Winapi," fullword ascii

	condition:
		( uint16(0)==0xbbef and filesize <200KB and 2 of them ) or (4 of them )
}
