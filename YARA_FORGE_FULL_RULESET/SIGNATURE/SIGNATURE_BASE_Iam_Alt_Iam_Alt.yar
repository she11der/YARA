rule SIGNATURE_BASE_Iam_Alt_Iam_Alt : FILE
{
	meta:
		description = "Auto-generated rule - file iam-alt.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "cf8ec963-ed23-531e-8ea2-ff9f8643aa75"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_passthehashtoolkit.yar#L33-L54"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2ea662ef58142d9e340553ce50d95c1b7a405672acdfd476403a565bdd0cfb90"
		logic_hash = "acd4dae57e8394d4ce2f3dfb44706ea35c3d684ab34fd0c707b6aeedd816280a"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii
		$s1 = "IAM-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii
		$s2 = "This tool allows you to change the NTLM credentials of the current logon session" fullword ascii
		$s3 = "username:domainname:lmhash:nthash" fullword ascii
		$s4 = "Error in cmdline!. Bye!." fullword ascii
		$s5 = "Error: Cannot open LSASS.EXE!." fullword ascii
		$s6 = "nthash is too long!." fullword ascii
		$s7 = "LSASS HANDLE: %x" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <240KB and 2 of them
}
