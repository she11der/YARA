rule SIGNATURE_BASE_HKTL_Lazycat_Logeraser
{
	meta:
		description = "Detetcs a tool used in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		id = "a3d74657-a389-5482-ab26-966e790afd50"
		date = "2019-02-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_aus_parl_compromise.yar#L113-L135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2b4b69dd675172b9b0c08fac674b6daa107535694b4073750501627fb48d12c2"
		score = 75
		quality = 35
		tags = ""
		hash1 = "1c113dce265e4d744245a7c55dadc80199ae972a9e0ecbd0c5ced57067cf755b"
		hash2 = "510375f8142b3651df67d42c3eff8d2d880987c0e057fc75a5583f36de34bf0e"

	strings:
		$x1 = "LazyCat.dll" ascii wide fullword
		$x2 = ".local_privilege_escalation.rotten_potato" ascii wide
		$x3 = "LazyCat.Extension" ascii wide
		$x4 = " MEOWof" ascii wide
		$x5 = "VirtualSite: {0}, Address: {1:X16}, Name: {2}, Handle: {3:X16}, LogPath: {4}" fullword wide
		$s1 = "LazyCat" fullword ascii wide
		$s2 = "$e3ff37f2-85d7-4b24-a385-7eeb1f5a9562"
		$s3 = "local -> remote {0} bytes"
		$s4 = "remote -> local {0} bytes"

	condition:
		3 of them
}
