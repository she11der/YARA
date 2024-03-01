rule SIGNATURE_BASE_Powershell_Emp_Eval_Jul17_A1 : FILE
{
	meta:
		description = "Detects suspicious sample with PowerShell content "
		author = "Florian Roth (Nextron Systems)"
		id = "1699f153-f972-5e06-a94b-eb95af637e6b"
		date = "2017-07-27"
		modified = "2023-12-05"
		reference = "PowerShell Empire Eval"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_ps_empire_eval.yar#L11-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e77ff4e216601c62a049569a6ea1aae13fc2612b480f4d7fad4e99dc72155da3"
		score = 65
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4d10e80c7c80ef040efc680424a429558c7d76a965685bbc295908cb71137eba"

	strings:
		$s1 = "powershell" wide
		$s2 = "pshcmd" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and all of them )
}
