rule SIGNATURE_BASE_Empire_Invoke_Shellcodemsil : FILE
{
	meta:
		description = "Detects Empire component - file Invoke-ShellcodeMSIL.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "06011b51-bad7-5656-ac37-e49f9b6d0498"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_empire.yar#L91-L107"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "eb556fb8b558145e7e981ab3c3ccfb2656512498b917c705e53bc5b9f3650155"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9a9c6c9eb67bde4a8ce2c0858e353e19627b17ee2a7215fa04a19010d3ef153f"

	strings:
		$s1 = "$FinalShellcode.Length" fullword ascii
		$s2 = "@(0x60,0xE8,0x04,0,0,0,0x61,0x31,0xC0,0xC3)" fullword ascii
		$s3 = "@(0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57," fullword ascii
		$s4 = "$TargetMethod.Invoke($null, @(0x11112222)) | Out-Null" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <30KB and 1 of them ) or all of them
}
