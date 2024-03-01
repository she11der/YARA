rule SIGNATURE_BASE_Bin_Ndisk : FILE
{
	meta:
		description = "Hacking Team Disclosure Sample - file ndisk.sys"
		author = "Florian Roth (Nextron Systems)"
		id = "f442315e-67c2-55a5-954e-8e7e48aa1243"
		date = "2015-07-07"
		modified = "2023-12-05"
		reference = "https://www.virustotal.com/en/file/a03a6ed90b89945a992a8c69f716ec3c743fa1d958426f4c50378cca5bef0a01/analysis/1436184181/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_hackingteam_rules.yar#L10-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cf5089752ba51ae827971272a5b761a4ab0acd84"
		logic_hash = "d93147e9631065eab35cbbc4ce112cfef92f81063cf8570bc021fbfe72811ab6"
		score = 100
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\Registry\\Machine\\System\\ControlSet00%d\\services\\ndisk.sys" fullword wide
		$s2 = "\\Registry\\Machine\\System\\ControlSet00%d\\Enum\\Root\\LEGACY_NDISK.SYS" fullword wide
		$s3 = "\\Driver\\DeepFrz" wide
		$s4 = "Microsoft Kernel Disk Manager" fullword wide
		$s5 = "ndisk.sys" fullword wide
		$s6 = "\\Device\\MSH4DEV1" wide
		$s7 = "\\DosDevices\\MSH4DEV1" wide
		$s8 = "built by: WinDDK" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <30KB and 6 of them
}
