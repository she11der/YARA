rule SIGNATURE_BASE_Regin_Sample_Set_1 : FILE
{
	meta:
		description = "Detects Regin Backdoor sample"
		author = "@MalwrSignatures"
		id = "b0f24a0b-10e7-5549-a300-516df8644cb0"
		date = "2014-11-27"
		modified = "2023-01-06"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_regin_fiveeyes.yar#L265-L295"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7402f409e7dd3180d8e6fe017af19d0a1d0dd86f85279191db1bc8f6c94951ac"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be"
		hash2 = "e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"

	strings:
		$hd = { fe ba dc fe }
		$s0 = "d%ls%ls" fullword wide
		$s1 = "\\\\?\\UNC" fullword wide
		$s2 = "Software\\Microsoft\\Windows\\CurrentVersion" fullword wide
		$s4 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" fullword wide
		$s5 = "System\\CurrentControlSet\\Services\\Tcpip\\Linkage" wide fullword
		$s6 = "\\\\.\\Global\\%s" fullword wide
		$s7 = "temp" fullword wide
		$s8 = "\\\\.\\%s" fullword wide
		$s9 = "Memory location: 0x%p, size 0x%08x" fullword wide
		$s10 = "sscanf" fullword ascii
		$s11 = "disp.dll" fullword ascii
		$s12 = "%x:%x:%x:%x:%x:%x:%x:%x%c" fullword ascii
		$s13 = "%d.%d.%d.%d%c" fullword ascii
		$s14 = "imagehlp.dll" fullword ascii
		$s15 = "%hd %d" fullword ascii

	condition:
		($hd at 0) and all of ($s*) and filesize <450KB and filesize >360KB
}
