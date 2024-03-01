rule SIGNATURE_BASE_Iam_Iam : FILE
{
	meta:
		description = "Auto-generated rule - file iam.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "15e8ddac-af17-5509-b552-b4364af57c90"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_passthehashtoolkit.yar#L94-L114"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8a8fcce649259f1b670bb1d996f0d06f6649baa8eed60db79b2c16ad22d14231"
		logic_hash = "f170f6f71b81a674a269ddd441c77a43afbbfe2870e1d0c4101abd2e58bff0b0"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii
		$s2 = "iam.exe -h administrator:mydomain:" ascii
		$s3 = "An error was encountered when trying to change the current logon credentials!." fullword ascii
		$s4 = "optional parameter. If iam.exe crashes or doesn't work when run in your system, use this parameter." fullword ascii
		$s5 = "IAM.EXE will try to locate some memory locations instead of using hard-coded values." fullword ascii
		$s6 = "Error in cmdline!. Bye!." fullword ascii
		$s7 = "Checking LSASRV.DLL...." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
